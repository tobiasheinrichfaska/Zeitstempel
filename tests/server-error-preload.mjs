// Preload for `tests/main-server-error.test.ts` (node --import): after the server of the relay is listening, it
// emits an error of the running server (as when no file descriptors are left for a new connection).
import http from 'node:http';

const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  const result = listen.apply(this, args);
  this.once('listening', () => {
    setTimeout(
      () => this.emit('error', Object.assign(new Error('injected'), { code: 'EMFILE' })),
      300,
    );
  });
  return result;
};
