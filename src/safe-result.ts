import {AuthSureFlowClientError} from './errors.js';

/**
 * Result object for safe methods.
 */
export interface SafeResult<T> {
  /**
   * True if the operation was successful.
   */
  readonly success: boolean;
  /**
   * The error if the operation was not successful.
   */
  readonly error: AuthSureFlowClientError | null;
  /**
   * The result of the operation if successful.
   */
  readonly result: T | null;
}
