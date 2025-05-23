#include <opus-psi/ChannelWrapper.h>

//#include <android/log.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace OpusPsi {

CSocketChannel::CSocketChannel(const char *hostname, uint16_t port,
                               bool isServer)
    : csocket(-1), serversocket(-1) {
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  if (hostname == nullptr && isServer)
    sockaddr.sin_addr.s_addr = INADDR_ANY;
  else
    sockaddr.sin_addr.s_addr = inet_addr(hostname);
  sockaddr.sin_port = htons(port);

  if (isServer) {
    struct sockaddr_in other;
    socklen_t otherlen = sizeof(struct sockaddr_in);
    serversocket = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(serversocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
               sizeof(reuse));

#ifdef SO_REUSEPORT
    setsockopt(serversocket, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse,
               sizeof(reuse));
#endif
    bind(serversocket, (struct sockaddr *)&sockaddr,
         sizeof(struct sockaddr_in));
    listen(serversocket, 1);
    csocket = accept(serversocket, (struct sockaddr *)&other, &otherlen);

  } else {
    csocket = socket(AF_INET, SOCK_STREAM, 0);
    while (connect(csocket, (struct sockaddr *)&sockaddr,
                   sizeof(struct sockaddr_in)) < 0)
      ;
    // TODO: add timeout instead of waiting forever
  }
}

CSocketChannel::~CSocketChannel() {
  if (serversocket >= 0) close(serversocket);
  if (csocket >= 0) close(csocket);
}

void CSocketChannel::send_all(uint8_t *data, size_t length) {
  size_t totalsent = 0;
  while (totalsent < length) {
    ssize_t sent = ::send(csocket, data + totalsent,
                          MIN(length - totalsent, 1024 * 1024ULL), 0);
    if (sent < 0) throw std::runtime_error("socket sent error, sent < 0");
    totalsent += sent;
  }
  bytes_sent += length;
}

void CSocketChannel::recv_all(uint8_t *data, size_t length) {
  size_t bytes_recvd = 0;
  while (bytes_recvd < length) {
    ssize_t recvd = ::recv(csocket, data + bytes_recvd,
                           MIN(length - bytes_recvd, 1024 * 1024ULL), 0);
    if (recvd < 0) throw std::runtime_error("socket recv error");
    bytes_recvd += recvd;
  }
  bytes_recv += length;
}

void CSocketChannel::sendAsync(std::vector<block> &data) {
  assert(false);
  //        size_t bytes = data.size() * sizeof(block);
  //        uint8_t* buf = (uint8_t*) data.data();
  //        send_all(buf, bytes);
}

void CSocketChannel::send(const std::vector<block> &data) {
  size_t bytes = data.size() * sizeof(block);
  uint8_t *buf = (uint8_t *)data.data();
  send_all(buf, bytes);
}

void CSocketChannel::send(const block &data) {
  size_t bytes = sizeof(block);
  uint8_t *buf = (uint8_t *)&data;
  send_all(buf, bytes);
}

void CSocketChannel::send(uint8_t *data, size_t length) {
  send_all(data, length);
}

void CSocketChannel::recvAsync(uint8_t *data, size_t length) { assert(false); }

void CSocketChannel::recv(uint8_t *data, size_t length) {
  recv_all(data, length);
}

void CSocketChannel::recv(block &data) {
  size_t bytes = sizeof(block);
  uint8_t *buf = (uint8_t *)&data;
  recv_all(buf, bytes);
}

void CSocketChannel::recv(std::vector<block> &data) {
  size_t bytes = data.size() * sizeof(block);
  uint8_t *buf = (uint8_t *)data.data();
  recv_all(buf, bytes);
}

//----------------------------------------------------------------------------------------------------------------------
void BufferChannel::sendAsync(std::vector<block> &data) { assert(false); }

void BufferChannel::send(const std::vector<block> &data) {
  auto len = data.size() * sizeof(block);
  buffer.insert(buffer.end(), (const uint8_t *)data.data(),
                ((const uint8_t *)data.data()) + len);
}

void BufferChannel::send(const block &data) {
  buffer.insert(buffer.end(), (const uint8_t *)&data,
                ((const uint8_t *)&data) + sizeof(block));
}

void BufferChannel::send(uint8_t *data, size_t length) {
  buffer.insert(buffer.end(), data, data + length);
}

void BufferChannel::recvAsync(uint8_t *data, size_t length) { assert(false); }

void BufferChannel::recv(uint8_t *data, size_t length) {
  assert(buffer.size() >= length);
  std::copy_n(buffer.begin(), length, data);
  buffer.erase(buffer.begin(), buffer.begin() + length);
}

void BufferChannel::recv(block &data) {
  assert(buffer.size() >= sizeof(block));
  std::copy_n(buffer.begin(), sizeof(block), (uint8_t *)&data);
  buffer.erase(buffer.begin(), buffer.begin() + sizeof(block));
}

void BufferChannel::recv(std::vector<block> &data) {
  auto len = data.size() * sizeof(block);
  assert(buffer.size() >= len);
  std::copy_n(buffer.begin(), len, (uint8_t *)data.data());
  buffer.erase(buffer.begin(), buffer.begin() + len);
}

std::vector<uint8_t> BufferChannel::getBuffer() {
  return std::vector<uint8_t>(buffer.begin(), buffer.end());
}

void BufferChannel::setBuffer(const std::vector<uint8_t> &buf) {
  buffer.assign(buf.begin(), buf.end());
}

}
