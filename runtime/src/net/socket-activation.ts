export function activatedSocketFd(): number | null {
  const count = Number(process.env.LISTEN_FDS ?? '0');
  const pid = Number(process.env.LISTEN_PID ?? '0');
  return count > 0 && pid === process.pid ? 3 : null;
}
