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
    this._iv = null;
  }

  setKey(keyId, encryptionKey) {
    this._key_id = keyId;
    this._encryption_key = Buffer.from(encryptionKey, 'hex');
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
    return this._iv.subarray(4);
  }

  _operateLock(key, encrypt = true) {
    return new Promise<void>(async (resolve, reject) => {
      let req_buf;
      if (!encrypt) {
        req_buf = Buffer.from(
          key.substring(0,2) + "000000" + key.substring(2), 'hex'
        );
      } else {
        const iv = await this._getIv();
        req_buf = Buffer.from(
          key.substring(0,2) + this._key_id + Buffer.from(iv.subarray(0,2)).toString('hex') + this._encrypt(key.substring(2))
        , 'hex');
      }

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
  }
}
