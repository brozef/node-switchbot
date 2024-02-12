/* Copyright(C) 2024, donavanbecker (https://github.com/donavanbecker). All rights reserved.
 *
 * wosmartlock.ts: Switchbot BLE API registration.
 */
import { Buffer } from 'buffer';

import { SwitchbotDevice } from '../device.js';
import * as Crypto from 'crypto';

export class WoSmartLock extends SwitchbotDevice {
  _iv;
  _key_id;
  _encryption_key;

  static COMMAND_GET_CK_IV = '570f2103';
  static COMMAND_LOCK_INFO = '570f4f8101';
  static COMMAND_UNLOCK = '570f4e01011080';
  static COMMAND_UNLOCK_NO_UNLATCH = '570f4e010110a0';
  static COMMAND_LOCK = '570f4e01011000';

  static parseServiceData(manufacturerData, onlog) {
    if (manufacturerData.length !== 6) {
      if (onlog && typeof onlog === 'function') {
        onlog(
          `[parseServiceDataForWoSmartLock] Buffer length ${manufacturerData.length} !== 6!`,
        );
      }
      return null;
    }
    const byte2 = manufacturerData.readUInt8(2);
    const byte7 = manufacturerData.readUInt8(7);
    const byte8 = manufacturerData.readUInt8(8);


    const LockStatus = {
      LOCKED: 0b0000000,
      UNLOCKED: 0b0010000,
      LOCKING: 0b0100000,
      UNLOCKING: 0b0110000,
      LOCKING_STOP: 0b1000000,
      UNLOCKING_STOP: 0b1010000,
      NOT_FULLY_LOCKED: 0b1100000,  //Only EU lock type
    };

    const battery = byte2 & 0b01111111; // %
    const calibration = byte7 & 0b10000000 ? true : false;
    const status = LockStatus[byte7 & 0b01110000];
    const update_from_secondary_lock = byte7 & 0b00001000 ? true : false;
    const door_open = byte7 & 0b00000100 ? true : false;
    const double_lock_mode = byte8 & 0b10000000 ? true : false;
    const unclosed_alarm = byte8 & 0b00100000 ? true : false;
    const unlocked_alarm = byte8 & 0b00010000 ? true : false;
    const auto_lock_paused = byte8 & 0b00000010 ? true : false;

    const data = {
      model: 'o',
      modelName: 'WoSmartLock',
      battery: battery,
      calibration: calibration,
      status: status,
      update_from_secondary_lock: update_from_secondary_lock,
      door_open: door_open,
      double_lock_mode: double_lock_mode,
      unclosed_alarm: unclosed_alarm,
      unlocked_alarm: unlocked_alarm,
      auto_lock_paused: auto_lock_paused,
    };

    return data;
  }

  constructor(peripheral, noble) {
    super(peripheral, noble);
    this._iv = null;
  }

    /* ------------------------------------------------------------------
   * setKey()
   * - initialise the encryption key info for valid lock communication, this currently must be retrived externally 
   *
   * [Arguments]
   * - keyId, encryptionKey
   *
   * [Return value]
   * - void
   * ---------------------------------------------------------------- */
  setKey(keyId, encryptionKey) {
    this._key_id = keyId;
    this._encryption_key = Buffer.from(encryptionKey, 'hex');
  }

  /* ------------------------------------------------------------------
   * unlock()
   * - Unlock the Smart Lock
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   Nothing will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  unlock() {
    return this._operateLock(WoSmartLock.COMMAND_UNLOCK);
  }

    /* ------------------------------------------------------------------
   * unlock_no_unlatch()
   * - Unlock the Smart Lock without unlatching door (eu version only)
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   Nothing will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  unlock_no_unlatch() {
    return this._operateLock(WoSmartLock.COMMAND_UNLOCK_NO_UNLATCH);
  }

  /* ------------------------------------------------------------------
   * lock()
   * - Lock the Smart Lock
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   Nothing will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  lock() {
    return this._operateLock(WoSmartLock.COMMAND_LOCK);
  }

    /* ------------------------------------------------------------------
   * info()
   * - Get general state info from the Smart Lock
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   resolves buffer to be parsed
   * ---------------------------------------------------------------- */
  info() {
    return this._operateLock(WoSmartLock.COMMAND_LOCK_INFO);
  }
  
  _encrypt(str) {
    const cipher = Crypto.createCipheriv("aes-128-ctr", this._encryption_key, this._iv);
    return Buffer.concat([cipher.update(str, 'hex'), cipher.final()]).toString('hex');
  }

  _decrypt(data) {
    const decipher = Crypto.createDecipheriv("aes-128-ctr", this._encryption_key, this._iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  async _getIv() {
    if (this._iv == null) {
        const res:Buffer = await this._operateLock(WoSmartLock.COMMAND_GET_CK_IV + this._key_id, false);
        this._iv = res.subarray(4);
    }
    return this._iv;
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
          const code = (res_buf as Buffer).readUInt8(0);
          if (code === 0x01) {
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
