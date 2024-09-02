package plugintest

import (
	"regexp"
	"strings"
	"testing"

	"github.com/robertkrimen/otto"
	"github.com/stretchr/testify/require"
)

func requireIsRegex(t *testing.T, pattern string) {
	t.Helper()

	_, err := regexp.Compile(pattern)
	require.NoError(t, err)
}

func requireIsJSRegex(t *testing.T, pattern string) {
	t.Helper()

	vm := otto.New()
	_, err := vm.Run(`
		var isValid = true;
		try {
			new RegExp("` + strings.ReplaceAll(pattern, "\\", "\\\\") + `");
		} catch(e) {
			isValid = false;
		}
	`)
	require.NoError(t, err)

	value, err := vm.Get("isValid")
	require.NoError(t, err)

	valueString, err := value.ToBoolean()
	require.NoError(t, err)

	require.True(t, valueString, "Pattern %q should be a valid JS regex", pattern)
}

func jsRegexMatches(t *testing.T, pattern, example string) bool {
	t.Helper()

	vm := otto.New()
	_, err := vm.Run(`
		var input = "` + example + `";
		regexp = new RegExp("` + strings.ReplaceAll(pattern, "\\", "\\\\") + `");
		result = regexp.test(input);
	`)
	require.NoError(t, err)

	value, err := vm.Get("result")
	require.NoError(t, err)

	valueString, err := value.ToBoolean()
	require.NoError(t, err)

	return valueString
}
