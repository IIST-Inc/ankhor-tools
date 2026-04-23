const USB_VENDOR_ID = 0x38ae;
const BAUD_RATE = 921600;

const ACK_FRAME = Uint8Array.from([0x00, 0x00, 0xff, 0x00, 0xff, 0x00]);
const NACK_FRAME = Uint8Array.from([0x00, 0x00, 0xff, 0xff, 0x00, 0x00]);

// Hard-coded command frames extracted from the private ankhor_js tool.
const INFO_FRAME = Uint8Array.from([0x00, 0x00, 0xff, 0x02, 0xfe, 0xd4, 0x00, 0x2c, 0x00]);
const TRNG_FRAME = Uint8Array.from([0x00, 0x00, 0xff, 0x02, 0xfe, 0xd4, 0x01, 0x2b, 0x00]);

const textDecoder = new TextDecoder();

function bytesToHex(buf, spaced = true) {
  return Array.from(buf, (value) => value.toString(16).padStart(2, "0").toUpperCase()).join(spaced ? " " : "");
}

function cleanText(text) {
  return text.replace(/\0+$/g, "").replace(/[^\x20-\x7E\r\n\t]+/g, "").trim();
}

function getPortLabel(port) {
  const info = port?.getInfo ? port.getInfo() : {};
  if (info?.usbVendorId) {
    const vendor = `0x${info.usbVendorId.toString(16)}`;
    const product = info.usbProductId !== undefined ? `0x${info.usbProductId.toString(16)}` : "-";
    return `${vendor}:${product}`;
  }
  return "Selected port";
}

async function requestPort(useFilter) {
  if (!("serial" in navigator)) {
    throw new Error("WebSerial unavailable");
  }

  if (useFilter) {
    return navigator.serial.requestPort({
      filters: [{ usbVendorId: USB_VENDOR_ID }],
    });
  }

  return navigator.serial.requestPort();
}

function checksumValid(buf, offset, len) {
  let sum = 0;
  for (let i = 0; i < len; i += 1) {
    sum = (sum + buf[offset + i]) & 0xff;
  }
  return sum === 0;
}

function readCString(buf, offset) {
  let end = buf.indexOf(0, offset);
  if (end === -1) end = buf.length;
  return cleanText(textDecoder.decode(buf.slice(offset, end)));
}

function parseDeviceInfo(rsp) {
  if (rsp.length < 2 || rsp[0] !== 0x00 || rsp[1] !== 0x00) {
    throw new Error("device info failed");
  }

  const payload = rsp.slice(2);
  const modelLen = payload.length === 100 ? 17 : payload.length === 97 ? 14 : 0;
  if (!modelLen || rsp.length < 2 + modelLen + 32 + 32 + 3) {
    throw new Error("device info parse failed");
  }

  let offset = 2;
  const model = cleanText(textDecoder.decode(rsp.slice(offset, offset + modelLen)));
  offset += modelLen;
  const name = readCString(rsp, offset);
  offset += 32;
  const uid = bytesToHex(rsp.slice(offset, offset + 32), false).toLowerCase();
  offset += 32;
  const fw = `${rsp[offset]}.${rsp[offset + 1]}.${rsp[offset + 2]}`;
  offset += 3;
  const sesip = cleanText(textDecoder.decode(rsp.slice(offset)));

  return { model, name, uid, fw, sesip };
}

class AnkhorVerifier {
  constructor() {
    this.port = null;
    this.reader = null;
    this.writer = null;
    this.reading = false;
    this.disconnecting = false;
    this.rxBuf = new Uint8Array();
    this.ackResolver = null;
    this.pending = null;
  }

  get connected() {
    return Boolean(this.port);
  }

  async connect(useFilter) {
    if (this.connected) return;
    if (!("serial" in navigator)) {
      throw new Error("WebSerial unavailable");
    }
    if (!window.isSecureContext) {
      throw new Error("WebSerial requires https or localhost");
    }

    const port = await requestPort(useFilter);

    await port.open({
      baudRate: BAUD_RATE,
      dataBits: 8,
      stopBits: 1,
      parity: "none",
      flowControl: "none",
      bufferSize: 4096,
    });

    this.port = port;
    this.writer = port.writable.getWriter();
    this.reader = port.readable.getReader();
    this.reading = true;
    this.disconnecting = false;
    void this.readLoop();
    return { port };
  }

  async disconnect() {
    if (this.disconnecting) return;
    this.disconnecting = true;
    this.reading = false;

    if (this.reader) {
      try {
        await this.reader.cancel();
      } catch (_) {
      }
      this.reader.releaseLock();
      this.reader = null;
    }

    if (this.writer) {
      try {
        await this.writer.close();
      } catch (_) {
      }
      this.writer.releaseLock();
      this.writer = null;
    }

    if (this.port) {
      try {
        await this.port.close();
      } catch (_) {
      }
      this.port = null;
    }

    this.rxBuf = new Uint8Array();
    this.resolveAck("timeout");
    this.rejectPending(new Error("disconnected"));
    this.disconnecting = false;
  }

  async readLoop() {
    while (this.reading && this.reader) {
      try {
        const { value, done } = await this.reader.read();
        if (done) break;
        if (value?.length) {
          this.appendRx(value);
          this.processBuffer();
        }
      } catch (_) {
        break;
      }
    }

    if (this.port && !this.disconnecting) {
      await this.disconnect();
      onConnectionChanged(false);
    }
  }

  appendRx(chunk) {
    const next = new Uint8Array(this.rxBuf.length + chunk.length);
    next.set(this.rxBuf, 0);
    next.set(chunk, this.rxBuf.length);
    this.rxBuf = next;
  }

  trimRx(count) {
    this.rxBuf = this.rxBuf.slice(count);
  }

  startsWith(expected) {
    if (this.rxBuf.length < expected.length) return false;
    return expected.every((value, index) => this.rxBuf[index] === value);
  }

  processBuffer() {
    while (this.rxBuf.length >= ACK_FRAME.length) {
      if (this.startsWith(ACK_FRAME)) {
        this.resolveAck("ok");
        this.trimRx(ACK_FRAME.length);
        continue;
      }

      if (this.startsWith(NACK_FRAME)) {
        this.resolveAck("nack");
        this.trimRx(NACK_FRAME.length);
        continue;
      }

      if (!(this.rxBuf[0] === 0x00 && this.rxBuf[1] === 0x00 && this.rxBuf[2] === 0xff)) {
        this.trimRx(1);
        continue;
      }

      if (!checksumValid(this.rxBuf, 3, 2)) {
        this.trimRx(3);
        continue;
      }

      const lenField = this.rxBuf[3];
      const pktLen = 7 + lenField;
      if (this.rxBuf.length < pktLen) {
        return;
      }

      if (this.rxBuf[pktLen - 1] !== 0x00 || !checksumValid(this.rxBuf, 5, lenField + 1)) {
        this.trimRx(3);
        continue;
      }

      const tfi = this.rxBuf[5];
      const data = this.rxBuf.slice(6, 5 + lenField);
      this.trimRx(pktLen);

      if (tfi === 0xd5 && data.length) {
        this.resolvePending(new Uint8Array(data));
      } else if (tfi === 0x7f) {
        this.rejectPending(new Error("device error"));
      }
    }
  }

  waitForAck(timeoutMs = 500) {
    this.resolveAck("timeout");
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.ackResolver = null;
        resolve("timeout");
      }, timeoutMs);

      this.ackResolver = (status) => {
        clearTimeout(timer);
        this.ackResolver = null;
        resolve(status);
      };
    });
  }

  resolveAck(status) {
    if (this.ackResolver) {
      this.ackResolver(status);
    }
  }

  waitForResponse(expectCmd, timeoutMs = 2000) {
    if (this.pending) {
      throw new Error("request already in progress");
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error("timeout"));
      }, timeoutMs);

      this.pending = {
        expectCmd,
        resolve: (data) => {
          clearTimeout(timer);
          this.pending = null;
          resolve(data);
        },
        reject: (error) => {
          clearTimeout(timer);
          this.pending = null;
          reject(error);
        },
      };
    });
  }

  resolvePending(data) {
    if (!this.pending) return;
    if (data[0] !== this.pending.expectCmd) return;
    this.pending.resolve(data);
  }

  rejectPending(error) {
    if (this.pending) {
      this.pending.reject(error);
    }
  }

  async sendAndReceive(frame, expectCmd) {
    if (!this.writer) {
      throw new Error("not connected");
    }

    const responsePromise = this.waitForResponse(expectCmd);
    const ackPromise = this.waitForAck();

    await this.writer.write(frame);

    const ack = await ackPromise;
    if (ack !== "ok") {
      this.rejectPending(new Error("ack failed"));
      throw new Error("ack failed");
    }

    return responsePromise;
  }

  async getInfo() {
    const rsp = await this.sendAndReceive(INFO_FRAME, 0x00);
    return parseDeviceInfo(rsp);
  }

  async trng() {
    const rsp = await this.sendAndReceive(TRNG_FRAME, 0x01);
    if (rsp.length < 34 || rsp[1] !== 0x00) {
      throw new Error("trng failed");
    }
    return rsp.slice(2, 34);
  }
}

const connectBtn = document.getElementById("connect-btn");
const disconnectBtn = document.getElementById("disconnect-btn");
const infoBtn = document.getElementById("info-btn");
const trngBtn = document.getElementById("trng-btn");
const filterCheckbox = document.getElementById("filter-checkbox");
const statusPill = document.getElementById("status-pill");
const output = document.getElementById("output");

const verifier = new AnkhorVerifier();

function setBusy(busy) {
  connectBtn.disabled = busy || verifier.connected;
  disconnectBtn.disabled = busy || !verifier.connected;
  infoBtn.disabled = busy || !verifier.connected;
  trngBtn.disabled = busy || !verifier.connected;
}

function onConnectionChanged(connected) {
  statusPill.textContent = connected ? "Connected" : "Disconnected";
  statusPill.classList.toggle("pill-on", connected);
  statusPill.classList.toggle("pill-off", !connected);
  connectBtn.disabled = connected;
  disconnectBtn.disabled = !connected;
  infoBtn.disabled = !connected;
  trngBtn.disabled = !connected;
}

function showText(text) {
  output.value = text;
}

connectBtn.addEventListener("click", async () => {
  setBusy(true);
  try {
    const { port } = await verifier.connect(filterCheckbox.checked);
    onConnectionChanged(true);
    showText(["Port opened.", getPortLabel(port)].join("\n"));
  } catch (error) {
    onConnectionChanged(false);
    showText(error?.message || String(error));
  } finally {
    setBusy(false);
  }
});

disconnectBtn.addEventListener("click", async () => {
  setBusy(true);
  try {
    await verifier.disconnect();
    onConnectionChanged(false);
    showText("Disconnected");
  } catch (error) {
    showText(error?.message || String(error));
  } finally {
    setBusy(false);
  }
});

infoBtn.addEventListener("click", async () => {
  setBusy(true);
  try {
    const info = await verifier.getInfo();
    showText([
      `Model: ${info.model}`,
      `Name: ${info.name}`,
      `UID: ${info.uid}`,
      `FW: ${info.fw}`,
      `SESIP: ${info.sesip}`,
    ].join("\n"));
  } catch (error) {
    showText(error?.message || String(error));
  } finally {
    setBusy(false);
  }
});

trngBtn.addEventListener("click", async () => {
  setBusy(true);
  try {
    const data = await verifier.trng();
    showText(bytesToHex(data));
  } catch (error) {
    showText(error?.message || String(error));
  } finally {
    setBusy(false);
  }
});

if ("serial" in navigator) {
  navigator.serial.addEventListener("disconnect", async () => {
    if (verifier.connected) {
      await verifier.disconnect();
      onConnectionChanged(false);
      showText("Disconnected");
    }
  });
}

window.addEventListener("beforeunload", () => {
  void verifier.disconnect();
});

onConnectionChanged(false);

if (!("serial" in navigator)) {
  connectBtn.disabled = true;
  disconnectBtn.disabled = true;
  infoBtn.disabled = true;
  trngBtn.disabled = true;
  filterCheckbox.disabled = true;
  showText("Web browsers does not support USB device connection");
}
