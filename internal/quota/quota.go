package quota

import "errors"

// ErrDailyQuotaExceeded is returned by the API key store when a key has
// consumed its daily request allowance.
var ErrDailyQuotaExceeded = errors.New("daily quota exceeded")
