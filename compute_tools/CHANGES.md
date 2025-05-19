# Changes Summary: Graceful Termination of PgBouncer and Local Proxy

## Implementation Steps Completed

1. **Updated PgBouncer Configuration**:
   - Added `pidfile=/etc/pgbouncer/pid` setting to `compute/etc/pgbouncer.ini`
   - This allows PgBouncer to write its PID to a file that we can use for termination

2. **Updated `forward_termination_signal()` Function**:
   - Added code to terminate local_proxy by reading PID from `/etc/local_proxy/pid`
   - Added code to terminate pgbouncer by reading PID from `/etc/pgbouncer/pid`
   - Added error handling and proper logging for all error scenarios
   - Added directory creation to ensure PID file directories exist

3. **Added Utility Function**:
   - Added `ensure_pid_dir()` function to create directories for PID files if they don't exist

4. **Updated Terminate Endpoint Handler**:
   - Updated log message to indicate that all three processes (Postgres, pgbouncer, and local_proxy) are terminated

## Testing 

To test these changes:

1. Verify that pgbouncer is properly configured with the pidfile setting:
   - Check `/etc/pgbouncer.ini` on a running compute node
   - Verify that the PID file is being created at `/etc/pgbouncer/pid`

2. Test the terminate API call:
   - Start a compute node with PostgreSQL, pgbouncer, and local_proxy
   - Issue a terminate API call
   - Verify all three processes are terminated gracefully
   - Check logs for any errors in the termination process

3. Edge cases to test:
   - What happens if one of the services is not running
   - What happens if PID files are not present
   - What happens if PID files exist but processes are not running

## Impact

This change ensures clean shutdown of all compute components, preventing orphaned processes and potential port conflicts during restarts.