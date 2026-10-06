package cmd

import "log/slog"

// slogLevelWarn is the level one-off commands log Badger at: its startup
// chatter is noise in a command that prints its own result, and anything that
// matters comes back as an error.
const slogLevelWarn = slog.LevelWarn
