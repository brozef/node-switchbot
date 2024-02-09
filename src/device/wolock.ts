import { Buffer } from 'buffer';
import * as Crypto from 'crypto';

import { SwitchbotDevice } from '../switchbot.js';

export class WoLock extends SwitchbotDevice {
    _iv;
    _key_id;
    _encryption_key;

  static COMMAND_HEADER = "57";
  static COMMAND_GET_CK_IV = `${WoLock.COMMAND_HEADER}0f2103`
  static COMMAND_LOCK_INFO = `${WoLock.COMMAND_HEADER}0f4f8101`
  static COMMAND_UNLOCK = `${WoLock.COMMAND_HEADER}0f4e01011080`
  static COMMAND_UNLOCK_WITHOUT_UNLATCH = `${WoLock.COMMAND_HEADER}0f4e010110a0`
  static COMMAND_LOCK = `${WoLock.COMMAND_HEADER}0f4e01011000`
  static COMMAND_ENABLE_NOTIFICATIONS = `${WoLock.COMMAND_HEADER}0e01001e00008101`
  static COMMAND_DISABLE_NOTIFICATIONS = `${WoLock.COMMAND_HEADER}0e00`

  constructor(peripheral, noble) {
    super(peripheral, noble);
    console.log('LOCK!');
    this._iv = null;
  }

  setKey(keyId, encryptionKey) {
    this._key_id = keyId;
    this._encryption_key = encryptionKey;
  }

  /* ------------------------------------------------------------------
   * open()
   * - Open the curtain
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   Nothing will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  unlock() {
    return this._operateLock(WoLock.COMMAND_UNLOCK);
  }

  /* ------------------------------------------------------------------
   * close()
   * - close the curtain
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   Nothing will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  lock() {
    return this._operateLock(WoLock.COMMAND_LOCK);
  }

  info() {
    return this._operateLock(WoLock.COMMAND_LOCK_INFO);
  }

  /*
    def _parse_lock_data(data: bytes) -> dict[str, Any]:
        return {
            "calibration": bool(data[0] & 0b10000000),
            "status": LockStatus((data[0] & 0b01110000) >> 4),
            "door_open": bool(data[0] & 0b00000100),
            "unclosed_alarm": bool(data[1] & 0b00100000),
            "unlocked_alarm": bool(data[1] & 0b00010000),
        }

        await self._lock_unlock(
            COMMAND_UNLOCK, {LockStatus.UNLOCKED, LockStatus.UNLOCKING}
        )

        async def _lock_unlock(
        self, command: str, ignore_statuses: set[LockStatus]
    ) -> bool:
        status = self.get_lock_status()
        if status is None:
            await self.update()
            status = self.get_lock_status()
        if status in ignore_statuses:
            return True

        await self._enable_notifications()
        result = await self._send_command(command)
        status = self._check_command_result(result, 0, COMMAND_RESULT_EXPECTED_VALUES)

        # Also update the battery and firmware version
        if basic_data := await self._get_basic_info():
            self._last_full_update = time.monotonic()
            if len(basic_data) >= 3:
                self._update_parsed_data(self._parse_basic_data(basic_data))
            else:
                _LOGGER.warning("Invalid basic data received: %s", basic_data)
            self._fire_callbacks()

        return status

   async def _send_command(
        self, key: str, retry: int | None = None, encrypt: bool = True
    ) -> bytes | None:
        if not encrypt:
            return await super()._send_command(key[:2] + "000000" + key[2:], retry)

        result = await self._ensure_encryption_initialized()
        if not result:
            _LOGGER.error("Failed to initialize encryption")
            return None

        encrypted = (
            key[:2] + self._key_id + self._iv[0:2].hex() + self._encrypt(key[2:])
        )
         result = await super()._send_command(encrypted, retry)
        return result[:1] + self._decrypt(result[4:])

            def _get_cipher(self) -> Cipher:
        if self._cipher is None:
            self._cipher = Cipher(
                algorithms.AES128(self._encryption_key), modes.CTR(self._iv)
            )
        return self._cipher

    def _encrypt(self, data: str) -> str:
        if len(data) == 0:
            return ""
        encryptor = self._get_cipher().encryptor()
        return (encryptor.update(bytearray.fromhex(data)) + encryptor.finalize()).hex()

    def _decrypt(self, data: bytearray) -> bytes:
        if len(data) == 0:
            return b""
        decryptor = self._get_cipher().decryptor()
        return decryptor.update(data) + decryptor.finalize()
        */



      _encrypt(str) {
        const cipher = Crypto.createCipheriv("aes-128-ctr", this._encryption_key, this._iv);
        return Buffer.concat([cipher.update(str), cipher.final()]).toString('hex');
      }

      _decrypt(data) {
        const decipher = Crypto.createDecipheriv("aes-128-ctr", this._encryption_key, this._iv);
        return Buffer.concat([decipher.update(data), decipher.final()]);
      }

      async _getIv() {
        if (this._iv == null) {
            this._iv = await this._operateLock(WoLock.COMMAND_GET_CK_IV + this._key_id, false);
        }
        return this._iv;
      }

      async _buildRequest(key, encrypt) {
        let req_buf;
        if (!encrypt) {
          req_buf = Buffer.concat([
            key.substring(0, 2), "000000", key.substring(2)
          ]);
        } else {
          const iv = await this._getIv();
          req_buf = Buffer.concat([
            key.substring(0, 2), this._key_id, Buffer.from(iv.substring(0, 2)).toString('hex'), this._encrypt(key.substring(2))
          ]);
        }
        return req_buf;
      }

  _operateLock(key, encrypt = true) {
    return new Promise<void>((resolve, reject) => {
      this._buildRequest(key, encrypt)
        .then(req_buf => {
          this._command(req_buf)
            .then((res_buf: unknown) => {
              console.log((res_buf as Buffer).toString());
              const code = (res_buf as Buffer).readUInt8(0);
              if ((res_buf as Buffer).length === 3 && code === 0x01) {
                let res;
                if (encrypt) {
                  res = Buffer.concat([(res_buf as Buffer).subarray(0, 1), this._decrypt((res_buf as Buffer).subarray(4))]);
                } else {
                  res = res_buf;
                }
                resolve(res);
              } else {
                reject(
                  new Error(
                    "The device returned an error: 0x" + (res_buf as Buffer).toString("hex")
                  )
                );
              }
            })
            .catch((error) => {
              reject(error);
            });
        });
    });
  }
}
