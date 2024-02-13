/* Copyright(C) 2024, donavanbecker (https://github.com/donavanbecker). All rights reserved.
 *
 * wosmartlock.ts: Switchbot BLE API registration.
 */
import { SwitchbotDevice } from '../device.js';
import { Peripheral } from '@abandonware/noble';
import * as Crypto from 'crypto';

export class WoSmartLock extends SwitchbotDevice {
  _iv:any;
  _key_id:string;
  _encryption_key:any;

  static COMMAND_GET_CK_IV = '570f2103';
  static COMMAND_LOCK_INFO = '570f4f8101';
  static COMMAND_UNLOCK = '570f4e01011080';
  static COMMAND_UNLOCK_NO_UNLATCH = '570f4e010110a0';
  static COMMAND_LOCK = '570f4e01011000';

  static LockResult = {
    ERROR: 0x00,
    RESULT_SUCCESS: 0x01,
    RESULT_SUCCESS_LOW_BATTERY: 0x06
  };

  static parseLockResult(code: number)
  {
    switch (code) {
      case WoSmartLock.LockResult.RESULT_SUCCESS:
        return WoSmartLock.LockResult.RESULT_SUCCESS;
      case WoSmartLock.LockResult.RESULT_SUCCESS_LOW_BATTERY:
        return WoSmartLock.LockResult.RESULT_SUCCESS_LOW_BATTERY;
    }
    return WoSmartLock.LockResult.ERROR;
  }

  static parseServiceData(manufacturerData: Buffer, onlog: ((message: string) => void) | undefined) {
    if (manufacturerData.length !== 12) {
      if (onlog && typeof onlog === 'function') {
        onlog(
          `[parseServiceDataForWoSmartLock] Buffer length ${manufacturerData.length} !== 12!`,
        );
      }
      return null;
    }
    const byte2 = manufacturerData.readUInt8(2);
    const byte7 = manufacturerData.readUInt8(7);
    const byte8 = manufacturerData.readUInt8(8);

    function getStatus(code: number): string {
      switch (code) {
        case LockStatus.LOCKED:
          return 'LOCKED';
        case LockStatus.UNLOCKED:
          return 'UNLOCKED';
        case LockStatus.LOCKING:
          return 'LOCKING';
        case LockStatus.UNLOCKING:
          return 'UNLOCKING';
        case LockStatus.LOCKING_STOP:
          return 'LOCKING_STOP';
        case LockStatus.UNLOCKING_STOP:
          return 'UNLOCKING_STOP';
        case LockStatus.NOT_FULLY_LOCKED:
          return 'NOT_FULLY_LOCKED';
        default:
          return 'UNKNOWN';
      }
    }

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
    const status = getStatus(byte7 & 0b01110000);
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

  constructor(peripheral: Peripheral, noble: any) {
    super(peripheral, noble);
    this._iv = null;
    this._key_id = '';
    this._encryption_key = null;
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
  setKey(keyId: string, encryptionKey: string) {
    this._iv = null;
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
   *   WoSmartLock.LockResult will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  unlock() {
    return new Promise<number>((resolve, reject) => {
      this._operateLock(WoSmartLock.COMMAND_UNLOCK)
      .then((resBuf) => {
        const code = (resBuf as Buffer).readUInt8(0);
        resolve(WoSmartLock.parseLockResult(code));
      }).catch((error) => {
        reject(error);
      });
    });
  }

    /* ------------------------------------------------------------------
   * unlockNoUnlatch()
   * - Unlock the Smart Lock without unlatching door
   *
   * [Arguments]
   * - none
   *
   * [Return value]
   * - Promise object
   *   WoSmartLock.LockResult will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  unlockNoUnlatch() {
    return new Promise<number>((resolve, reject) => {
      this._operateLock(WoSmartLock.COMMAND_UNLOCK_NO_UNLATCH)
      .then((resBuf) => {
        const code = (resBuf as Buffer).readUInt8(0);
        resolve(WoSmartLock.parseLockResult(code));
      }).catch((error) => {
        reject(error);
      });
    });
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
   *   WoSmartLock.LockResult will be passed to the `resolve()`.
   * ---------------------------------------------------------------- */
  lock() {
    return new Promise<number>((resolve, reject) => {
      this._operateLock(WoSmartLock.COMMAND_LOCK)
      .then((resBuf) => {
        const code = (resBuf as Buffer).readUInt8(0);
        resolve(WoSmartLock.parseLockResult(code));
      }).catch((error) => {
        reject(error);
      });
    });
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
   *   state object will be passed to the `resolve()`
   * ---------------------------------------------------------------- */
  info() {
    return new Promise((resolve, reject) => {
      this._operateLock(WoSmartLock.COMMAND_LOCK_INFO)
      .then(resBuf => {
        resolve(WoSmartLock.parseServiceData(resBuf, () => {}));
      }).catch((error) => {
        reject(error);
      });
    });
  }
  
  _encrypt(str:string) {
    const cipher = Crypto.createCipheriv("aes-128-ctr", this._encryption_key, this._iv);
    return Buffer.concat([cipher.update(str, 'hex'), cipher.final()]).toString('hex');
  }

  _decrypt(data:Buffer) {
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

  _operateLock(key:string, encrypt:boolean = true) {
    return new Promise<Buffer>(async (resolve, reject) => {
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
          if ((res_buf as Buffer).length >= 3 && (code === 0x01 || code === 0x06)) { //6 is success but low battery
            let res;
            if (encrypt) {
              res = Buffer.concat([(res_buf as Buffer).subarray(0, 1), this._decrypt((res_buf as Buffer).subarray(4))]);
            } else {
              res = res_buf;
            }
            resolve(res as Buffer);
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

