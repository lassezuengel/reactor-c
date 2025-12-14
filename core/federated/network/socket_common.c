#include <unistd.h>      // Defines read(), write(), and close()
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdarg.h> //va_list
#include <string.h> // strerror

#ifdef PLATFORM_ZEPHYR
#include <zephyr/net/socket.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>  // IPPROTO_TCP, IPPROTO_UDP
#include <netinet/tcp.h> // TCP_NODELAY
#endif

#include "util.h"
#include "socket_common.h"

/** Number of nanoseconds to sleep before retrying a socket read. */
#define SOCKET_READ_RETRY_INTERVAL 1000000

// Mutex lock held while performing socket shutdown and close operations.
lf_mutex_t shutdown_mutex;

/**
 * Set the socket timeout options.
 * @param socket_descriptor The file descriptor of the socket on which to set options.
 * @param timeout_time A pointer to a `struct timeval` that specifies the timeout duration
 *                     for socket operations (receive and send).
 */
static void set_socket_timeout_option(int socket_descriptor, struct timeval* timeout_time) {
  // Set the option for this socket to reuse the same address
  int true_variable = 1; // setsockopt() requires a reference to the value assigned to an option
  if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &true_variable, sizeof(int32_t)) < 0) {
    lf_print_error("Failed to set SO_REUSEADDR option on the socket: %s.", strerror(errno));
  }
  // Set the timeout on the socket so that read and write operations don't block for too long
  if (setsockopt(socket_descriptor, SOL_SOCKET, SO_RCVTIMEO, (const char*)timeout_time, sizeof(*timeout_time)) < 0) {
    lf_print_error("Failed to set SO_RCVTIMEO option on the socket: %s.", strerror(errno));
  }
  if (setsockopt(socket_descriptor, SOL_SOCKET, SO_SNDTIMEO, (const char*)timeout_time, sizeof(*timeout_time)) < 0) {
    lf_print_error("Failed to set SO_SNDTIMEO option on the socket: %s.", strerror(errno));
  }
}

int create_server(uint16_t port, int* final_socket, uint16_t* final_port, socket_type_t sock_type,
                  bool increment_port_on_retry) {
  struct addrinfo* addrinfo_result = NULL;
  int socket_descriptor = -1;
  uint16_t used_port = port;

  if (port == 0 && increment_port_on_retry) {
    used_port = DEFAULT_PORT;
  }

  int bind_result = -1;
  int count = 0;

  // Retry logic for finding a port and binding
  while (bind_result != 0 && count++ < PORT_BIND_RETRY_LIMIT) {
    // Convert port to string for getaddrinfo
    char port_str[6]; // Max port number is 65535, so 5 digits + null terminator
    snprintf(port_str, sizeof(port_str), "%u", used_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
#ifdef USE_IPV6
    hints.ai_family = AF_INET6; // Force IPv6
#else
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
#endif
    hints.ai_socktype = (sock_type == TCP) ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = (sock_type == TCP) ? IPPROTO_TCP : IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE; // For wildcard IP address

    int result = getaddrinfo(NULL, port_str, &hints, &addrinfo_result);
    if (result != 0) {
        lf_print_error("getaddrinfo failed: %s", gai_strerror(result));
        if (addrinfo_result != NULL) freeaddrinfo(addrinfo_result);
        return -1;
    }

    // `getaddrinfo` returns a list of address structures.
    // Try each address until we successfully create and bind a socket.
    for (struct addrinfo* rp = addrinfo_result; rp != NULL; rp = rp->ai_next) {
        socket_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (socket_descriptor == -1) {
            lf_print_warning("Failed to create socket: %s. Trying next address.", strerror(errno));
            continue; // Try the next address
        }

        // Set socket options (like SO_REUSEADDR) BEFORE binding.
        struct timeval timeout_time;
        if (sock_type == TCP) {
        timeout_time =
            (struct timeval){.tv_sec = TCP_TIMEOUT_TIME / BILLION, .tv_usec = (TCP_TIMEOUT_TIME % BILLION) / 1000};
        } else {
        timeout_time =
            (struct timeval){.tv_sec = UDP_TIMEOUT_TIME / BILLION, .tv_usec = (UDP_TIMEOUT_TIME % BILLION) / 1000};
        }
        set_socket_timeout_option(socket_descriptor, &timeout_time);

        if (bind(socket_descriptor, rp->ai_addr, rp->ai_addrlen) == 0) {
            bind_result = 0; // Success
            break;
        }

        // Bind failed for this address, close the socket and try the next one.
        close(socket_descriptor);
        socket_descriptor = -1;
    }
    freeaddrinfo(addrinfo_result);
    addrinfo_result = NULL;

    if (socket_descriptor == -1) {
      lf_print_error("Failed to create a socket for port %d.", used_port);
      // Fall through to retry logic
    }

    if (bind_result != 0) {
      if (increment_port_on_retry) {
        lf_print_warning("Failed to bind to port %d.", used_port);
        used_port++;
        if (used_port >= DEFAULT_PORT + MAX_NUM_PORT_ADDRESSES)
          used_port = DEFAULT_PORT;
        lf_print_warning("Will try again with port %d.", used_port);
      } else {
        lf_print("Failed to bind socket on port %d. Will try again in " PRINTF_TIME " nsec.", used_port,
                 PORT_BIND_RETRY_INTERVAL);
        lf_sleep(PORT_BIND_RETRY_INTERVAL);
      }
    }
  }

  if (bind_result != 0) {
    lf_print_error_and_exit("Failed to bind the socket after multiple retries. Port %d may not be available.", port);
  }

  // For TCP, set real-time options and listen
  if (sock_type == TCP) {
    int flag = 1;
    if (setsockopt(socket_descriptor, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0) {
      lf_print_error_system_failure("Failed to disable Nagle algorithm on socket server.");
    }
#if defined(PLATFORM_Linux)
    if (setsockopt(socket_descriptor, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(int)) < 0) {
      lf_print_error_system_failure("Failed to disable delayed ACKs on socket server.");
    }
#endif

    if (listen(socket_descriptor, 128)) {
      lf_print_error("Failed to listen on socket %d: %s.", socket_descriptor, strerror(errno));
      return -1;
    }
  }

  // If port was 0, get the port assigned by the OS
  if (port == 0) {
    struct sockaddr_storage assigned_addr;
    socklen_t addr_len = sizeof(assigned_addr);
    if (getsockname(socket_descriptor, (struct sockaddr*)&assigned_addr, &addr_len) < 0) {
      lf_print_error_and_exit("Federate failed to retrieve assigned port number.");
    }
    if (assigned_addr.ss_family == AF_INET) {
      used_port = ntohs(((struct sockaddr_in*)&assigned_addr)->sin_port);
    } else { // AF_INET6
      used_port = ntohs(((struct sockaddr_in6*)&assigned_addr)->sin6_port);
    }
  }

  lf_print_debug("Server socket is bound to port %d.", used_port);

  *final_socket = socket_descriptor;
  *final_port = used_port;

  return 0;
}

/**
 * Return true if either the socket to the RTI is broken or the socket is
 * alive and the first unread byte on the socket's queue is MSG_TYPE_FAILED.
 */
static bool check_socket_closed(int socket) {
  unsigned char first_byte;
  ssize_t bytes = peek_from_socket(socket, &first_byte);
  if (bytes < 0 || (bytes == 1 && first_byte == MSG_TYPE_FAILED)) {
    return true;
  } else {
    return false;
  }
}

int accept_socket(int socket, int rti_socket) {
  struct sockaddr client_fd;
  // Wait for an incoming connection request.
  uint32_t client_length = sizeof(client_fd);
  // The following blocks until a federate connects.
  int socket_id = -1;
  while (true) {
    // When close(socket) is called, the accept() will return -1.
    socket_id = accept(socket, &client_fd, &client_length);
    if (socket_id >= 0) {
      // Got a socket
      break;
    } else if (socket_id < 0 && (errno != EAGAIN || errno != EWOULDBLOCK || errno != EINTR)) {
      if (errno != ECONNABORTED) {
        lf_print_warning("Failed to accept the socket. %s.", strerror(errno));
      }
      break;
    } else if (errno == EPERM) {
      lf_print_error_system_failure("Firewall permissions prohibit connection.");
    } else {
      // For the federates, it should check if the rti_socket is still open, before retrying accept().
      if (rti_socket != -1) {
        if (check_socket_closed(rti_socket)) {
          break;
        }
      }
      // Try again
      lf_print_warning("Failed to accept the socket. %s. Trying again.", strerror(errno));
      continue;
    }
  }
  return socket_id;
}

int connect_to_socket(const char* hostname, int port, int* sock) {
  struct addrinfo *addrinfo_result, *rp;
  int socket_descriptor = -1;
  uint16_t used_port = (port == 0) ? DEFAULT_PORT : (uint16_t)port;

  instant_t start_connect = lf_time_physical();

  // As long as we are not timed out, try to connect
  while (1) {
    if (CHECK_TIMEOUT(start_connect, CONNECT_TIMEOUT)) {
      lf_print_error("Failed to connect to %s with timeout: " PRINTF_TIME ". Giving up.", hostname, CONNECT_TIMEOUT);
      return -1;
    }

    // Convert port to string for getaddrinfo
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", used_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
#ifdef USE_IPV6
    hints.ai_family = AF_INET6; // Force IPv6
#else
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
#endif
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP;

    int result = getaddrinfo(hostname, port_str, &hints, &addrinfo_result);
    if (result != 0) {
        lf_print_warning("getaddrinfo failed for %s:%d: %s. Will try again in " PRINTF_TIME " nsec.", hostname, used_port, gai_strerror(result), CONNECT_RETRY_INTERVAL);
        lf_sleep(CONNECT_RETRY_INTERVAL);
        continue;
    }

    // `getaddrinfo` returns a list of address structures.
    // Try each address until we successfully connect.
    for (rp = addrinfo_result; rp != NULL; rp = rp->ai_next) {
        socket_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (socket_descriptor == -1) {
            lf_print_warning("Failed to create socket for %s:%d: %s.", hostname, used_port, strerror(errno));
            continue; // Try the next address
        }

        if (connect(socket_descriptor, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // Success
        }

        // Connect failed.
        close(socket_descriptor);
        socket_descriptor = -1;
    }

    freeaddrinfo(addrinfo_result);

    if (socket_descriptor == -1) {
      // We failed to connect to any of the resolved addresses.
      lf_sleep(CONNECT_RETRY_INTERVAL);
      if (port == 0) {
        used_port++;
        if (used_port >= DEFAULT_PORT + MAX_NUM_PORT_ADDRESSES) {
          used_port = DEFAULT_PORT;
        }
      }
      lf_print_warning("Could not connect to %s:%d. Will try again in " PRINTF_TIME " nsec.", hostname, used_port,
                       CONNECT_RETRY_INTERVAL);
      continue;
    } else {
      // Success
      lf_print("Connected to %s:%d.", hostname, used_port);
      *sock = socket_descriptor;
      return 0;
    }
  }
  return -1; // Should be unreachable
}

int read_from_socket(int socket, size_t num_bytes, unsigned char* buffer) {
  if (socket < 0) {
    // Socket is not open.
    errno = EBADF;
    return -1;
  }
  ssize_t bytes_read = 0;
  while (bytes_read < (ssize_t)num_bytes) {
    ssize_t more = read(socket, buffer + bytes_read, num_bytes - (size_t)bytes_read);
    if (more < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      // Those error codes set by the socket indicates
      // that we should try again (@see man errno).
      LF_PRINT_DEBUG("Reading from socket %d failed with error: `%s`. Will try again.", socket, strerror(errno));
      lf_sleep(DELAY_BETWEEN_SOCKET_RETRIES);
      continue;
    } else if (more < 0) {
      // A more serious error occurred.
      lf_print_error("Reading from socket %d failed. With error: `%s`", socket, strerror(errno));
      return -1;
    } else if (more == 0) {
      // EOF received.
      return 1;
    }
    bytes_read += more;
  }
  return 0;
}

int read_from_socket_close_on_error(int* socket, size_t num_bytes, unsigned char* buffer) {
  assert(socket);
  int socket_id = *socket; // Assume atomic read so we don't pass -1 to read_from_socket.
  if (socket_id >= 0) {
    int read_failed = read_from_socket(socket_id, num_bytes, buffer);
    if (read_failed) {
      // Read failed.
      // Socket has probably been closed from the other side.
      // Shut down and close the socket from this side.
      shutdown_socket(socket, false);
      return -1;
    }
    return 0;
  }
  lf_print_warning("Socket is no longer connected. Read failed.");
  return -1;
}

void read_from_socket_fail_on_error(int* socket, size_t num_bytes, unsigned char* buffer, char* format, ...) {
  va_list args;
  assert(socket);
  int read_failed = read_from_socket_close_on_error(socket, num_bytes, buffer);
  if (read_failed) {
    // Read failed.
    if (format != NULL) {
      va_start(args, format);
      lf_print_error_system_failure(format, args);
      va_end(args);
    } else {
      lf_print_error_system_failure("Failed to read from socket.");
    }
  }
}

ssize_t peek_from_socket(int socket, unsigned char* result) {
  ssize_t bytes_read = recv(socket, result, 1, MSG_DONTWAIT | MSG_PEEK);
  if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  else
    return bytes_read;
}

int write_to_socket(int socket, size_t num_bytes, unsigned char* buffer) {
  if (socket < 0) {
    // Socket is not open.
    errno = EBADF;
    return -1;
  }
  ssize_t bytes_written = 0;
  while (bytes_written < (ssize_t)num_bytes) {
    ssize_t more = write(socket, buffer + bytes_written, num_bytes - (size_t)bytes_written);
    if (more <= 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      // The error codes EAGAIN or EWOULDBLOCK indicate
      // that we should try again (@see man errno).
      // The error code EINTR means the system call was interrupted before completing.
      LF_PRINT_DEBUG("Writing to socket %d was blocked. Will try again.", socket);
      lf_sleep(DELAY_BETWEEN_SOCKET_RETRIES);
      continue;
    } else if (more < 0) {
      // A more serious error occurred.
      lf_print_error("Writing to socket %d failed. With error: `%s`", socket, strerror(errno));
      return -1;
    }
    bytes_written += more;
  }
  return 0;
}

int write_to_socket_close_on_error(int* socket, size_t num_bytes, unsigned char* buffer) {
  assert(socket);
  int socket_id = *socket; // Assume atomic read so we don't pass -1 to write_to_socket.
  if (socket_id >= 0) {
    int result = write_to_socket(socket_id, num_bytes, buffer);
    if (result) {
      // Write failed.
      // Socket has probably been closed from the other side.
      // Shut down and close the socket from this side.
      shutdown_socket(socket, false);
      return -1;
    }
    return result;
  }
  lf_print_warning("Socket is no longer connected. Write failed.");
  return -1;
}

void write_to_socket_fail_on_error(int* socket, size_t num_bytes, unsigned char* buffer, lf_mutex_t* mutex,
                                   char* format, ...) {
  va_list args;
  assert(socket);
  int result = write_to_socket_close_on_error(socket, num_bytes, buffer);
  if (result) {
    // Write failed.
    if (mutex != NULL) {
      LF_MUTEX_UNLOCK(mutex);
    }
    if (format != NULL) {
      va_start(args, format);
      lf_print_error_system_failure(format, args);
      va_end(args);
    } else {
      lf_print_error_and_exit("Failed to write to socket. Shutting down.");
    }
  }
}

void init_shutdown_mutex(void) { LF_MUTEX_INIT(&shutdown_mutex); }

int shutdown_socket(int* socket, bool read_before_closing) {
  LF_MUTEX_LOCK(&shutdown_mutex);
  int result = 0;
  if (*socket < 0) {
    lf_print_log("Socket is already closed.");
  } else {
    if (!read_before_closing) {
      if (shutdown(*socket, SHUT_RDWR)) {
        lf_print_log("On shutdown socket, received reply: %s", strerror(errno));
        result = -1;
      } // else shutdown reads and writes succeeded.
    } else {
      // Signal the other side that no further writes are expected by sending a FIN packet.
      // This indicates the write direction is closed. For more details, refer to:
      // https://stackoverflow.com/questions/4160347/close-vs-shutdown-socket
      if (shutdown(*socket, SHUT_WR)) {
        lf_print_log("Failed to shutdown socket: %s", strerror(errno));
        result = -1;
      } else {
        // Shutdown writes succeeded.
        // Read any remaining bytes coming in on the socket until an EOF or socket error occurs.
        // Discard any incoming bytes. Normally, this read should return 0, indicating an EOF,
        // meaning that the peer has also closed the connection.
        // This compensates for delayed ACKs and scenarios where Nagle's algorithm is disabled,
        // ensuring the shutdown completes gracefully.
        unsigned char buffer[10];
        while (read(*socket, buffer, 10) > 0)
          ;
      }
    }
    // Attempt to close the socket.
    // NOTE: In all common TCP/IP stacks, there is a time period,
    // typically between 30 and 120 seconds, called the TIME_WAIT period,
    // before the port is released after this close. This is because
    // the OS is preventing another program from accidentally receiving
    // duplicated packets intended for this program.
    if (result != 0 && close(*socket)) {
      // Close failed.
      lf_print_log("Error while closing socket: %s\n", strerror(errno));
      result = -1;
    }
    *socket = -1;
  }
  LF_MUTEX_UNLOCK(&shutdown_mutex);
  return result;
}
