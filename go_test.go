package template

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHello(t *testing.T) {
	require.Equal(t, "hello world", hello())
}
