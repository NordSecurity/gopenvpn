package openvpn

import (
	"fmt"
	"testing"
)

// A key requirement of our event parsing is that it must never cause a
// panic, even if the OpenVPN process sends us malformed garbage.
//
// Therefore most of the tests in here are testing various tortured error
// cases, which are all expected to produce an event object, though the
// contents of that event object will be nonsensical if the OpenVPN server
// sends something nonsensical.

func TestMalformedEvent(t *testing.T) {
	tests := [][]byte{
		[]byte(""),
		[]byte("HTTP/1.1 200 OK"),
		[]byte("     "),
		[]byte("\x00"),
	}

	for i, test := range tests {
		event := upgradeEvent(test)

		malformed, ok := event.(*MalformedEvent)
		if !ok {
			t.Errorf("test %d got %T; want %T", i, event, malformed)
			continue
		}

		wantString := fmt.Sprintf("Malformed Event %q", test)
		if gotString := malformed.String(); gotString != wantString {
			t.Errorf("test %d String returned %q; want %q", i, gotString, wantString)
		}
	}
}

func TestUnknownEvent(t *testing.T) {
	tests := []struct {
		input    []byte
		wantType string
		wantBody string
	}{
		{
			input:    []byte("DUMMY:baz"),
			wantType: "DUMMY",
			wantBody: "baz",
		},
		{
			input:    []byte("DUMMY:"),
			wantType: "DUMMY",
			wantBody: "",
		},
		{
			input:    []byte("DUMMY:abc,123,456"),
			wantType: "DUMMY",
			wantBody: "abc,123,456",
		},
	}

	for i, test := range tests {
		event := upgradeEvent(test.input)

		unk, ok := event.(*UnknownEvent)
		if !ok {
			t.Errorf("test %d got %T; want %T", i, event, unk)
			continue
		}

		if got, want := unk.Type(), test.wantType; got != want {
			t.Errorf("test %d Type returned %q; want %q", i, got, want)
		}

		if got, want := unk.Body(), test.wantBody; got != want {
			t.Errorf("test %d Body returned %q; want %q", i, got, want)
		}
	}
}

func TestHoldEvent(t *testing.T) {
	tests := [][]byte{
		[]byte("HOLD:"),
		[]byte("HOLD:waiting for hold release"),
	}

	for i, test := range tests {
		event := upgradeEvent(test)

		if hold, ok := event.(*HoldEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, hold)
			continue
		}
	}
}

func TestEchoEvent(t *testing.T) {
	tests := []struct {
		input         []byte
		wantTimestamp string
		wantMessage   string
	}{
		{
			input:         []byte("ECHO:123,foo"),
			wantTimestamp: "123",
			wantMessage:   "foo",
		},
		{
			input:         []byte("ECHO:123,"),
			wantTimestamp: "123",
			wantMessage:   "",
		},
		{
			input:         []byte("ECHO:,foo"),
			wantTimestamp: "",
			wantMessage:   "foo",
		},
		{
			input:         []byte("ECHO:,"),
			wantTimestamp: "",
			wantMessage:   "",
		},
		{
			input:         []byte("ECHO:"),
			wantTimestamp: "",
			wantMessage:   "",
		},
	}

	for i, test := range tests {
		event := upgradeEvent(test.input)

		echo, ok := event.(*EchoEvent)
		if !ok {
			t.Errorf("test %d got %T; want %T", i, event, echo)
			continue
		}

		if got, want := echo.RawTimestamp(), test.wantTimestamp; got != want {
			t.Errorf("test %d RawTimestamp returned %q; want %q", i, got, want)
		}

		if got, want := echo.Message(), test.wantMessage; got != want {
			t.Errorf("test %d Message returned %q; want %q", i, got, want)
		}
	}
}

func TestStateEvent(t *testing.T) {
	tests := []struct {
		input          []byte
		wantTimestamp  string
		wantState      string
		wantDesc       string
		wantLocalAddr  string
		wantRemoteAddr string
	}{
		{
			input:          []byte("STATE:"),
			wantTimestamp:  "",
			wantState:      "",
			wantDesc:       "",
			wantLocalAddr:  "",
			wantRemoteAddr: "",
		},
		{
			input:          []byte("STATE:,"),
			wantTimestamp:  "",
			wantState:      "",
			wantDesc:       "",
			wantLocalAddr:  "",
			wantRemoteAddr: "",
		},
		{
			input:          []byte("STATE:,,,,"),
			wantTimestamp:  "",
			wantState:      "",
			wantDesc:       "",
			wantLocalAddr:  "",
			wantRemoteAddr: "",
		},
		{
			input:          []byte("STATE:123,CONNECTED,good,172.16.0.1,192.168.4.1"),
			wantTimestamp:  "123",
			wantState:      "CONNECTED",
			wantDesc:       "good",
			wantLocalAddr:  "172.16.0.1",
			wantRemoteAddr: "192.168.4.1",
		},
		{
			input:          []byte("STATE:123,RECONNECTING,SIGHUP,,"),
			wantTimestamp:  "123",
			wantState:      "RECONNECTING",
			wantDesc:       "SIGHUP",
			wantLocalAddr:  "",
			wantRemoteAddr: "",
		},
		{
			input:          []byte("STATE:123,RECONNECTING,SIGHUP,,,extra"),
			wantTimestamp:  "123",
			wantState:      "RECONNECTING",
			wantDesc:       "SIGHUP",
			wantLocalAddr:  "",
			wantRemoteAddr: "",
		},
	}

	for i, test := range tests {
		event := upgradeEvent(test.input)

		st, ok := event.(*StateEvent)
		if !ok {
			t.Errorf("test %d got %T; want %T", i, event, st)
			continue
		}

		if got, want := st.RawTimestamp(), test.wantTimestamp; got != want {
			t.Errorf("test %d RawTimestamp returned %q; want %q", i, got, want)
		}

		if got, want := st.NewState(), test.wantState; got != want {
			t.Errorf("test %d NewState returned %q; want %q", i, got, want)
		}

		if got, want := st.Description(), test.wantDesc; got != want {
			t.Errorf("test %d Description returned %q; want %q", i, got, want)
		}

		if got, want := st.LocalTunnelAddr(), test.wantLocalAddr; got != want {
			t.Errorf("test %d LocalTunnelAddr returned %q; want %q", i, got, want)
		}

		if got, want := st.RemoteAddr(), test.wantRemoteAddr; got != want {
			t.Errorf("test %d RemoteAddr returned %q; want %q", i, got, want)
		}
	}
}

func TestByteCountEvent(t *testing.T) {
	tests := []struct {
		input        []byte
		wantClientId string
		wantBytesIn  int
		wantBytesOut int
	}{
		{
			input:        []byte("BYTECOUNT:"),
			wantClientId: "",
			wantBytesIn:  0,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT:123,456"),
			wantClientId: "",
			wantBytesIn:  123,
			wantBytesOut: 456,
		},
		{
			input:        []byte("BYTECOUNT:,"),
			wantClientId: "",
			wantBytesIn:  0,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT:5,"),
			wantClientId: "",
			wantBytesIn:  5,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT:,6"),
			wantClientId: "",
			wantBytesIn:  0,
			wantBytesOut: 6,
		},
		{
			input:        []byte("BYTECOUNT:6"),
			wantClientId: "",
			wantBytesIn:  6,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT:wrong,bad"),
			wantClientId: "",
			wantBytesIn:  0,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT:1,2,3"),
			wantClientId: "",
			wantBytesIn:  1,
			wantBytesOut: 2,
		},
		{
			// Intentionally malformed BYTECOUNT event sent as BYTECOUNT_CLI
			input:        []byte("BYTECOUNT_CLI:123,456"),
			wantClientId: "123",
			wantBytesIn:  456,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT_CLI:"),
			wantClientId: "",
			wantBytesIn:  0,
			wantBytesOut: 0,
		},
		{
			input:        []byte("BYTECOUNT_CLI:abc123,123,456"),
			wantClientId: "abc123",
			wantBytesIn:  123,
			wantBytesOut: 456,
		},
		{
			input:        []byte("BYTECOUNT_CLI:abc123,123"),
			wantClientId: "abc123",
			wantBytesIn:  123,
			wantBytesOut: 0,
		},
	}

	for i, test := range tests {
		event := upgradeEvent(test.input)

		bc, ok := event.(*ByteCountEvent)
		if !ok {
			t.Errorf("test %d got %T; want %T", i, event, bc)
			continue
		}

		if got, want := bc.ClientId(), test.wantClientId; got != want {
			t.Errorf("test %d ClientId returned %q; want %q", i, got, want)
		}

		if got, want := bc.BytesIn(), test.wantBytesIn; got != want {
			t.Errorf("test %d BytesIn returned %d; want %d", i, got, want)
		}

		if got, want := bc.BytesOut(), test.wantBytesOut; got != want {
			t.Errorf("test %d BytesOut returned %d; want %d", i, got, want)
		}
	}
}

func TestPasswordEvent(t *testing.T) {
	tests := [][]byte{
		[]byte("PASSWORD:"),
		[]byte("PASSWORD:Need 'Private Key' password"),
		[]byte("PASSWORD:Need 'Auth' username/password"),
		[]byte("PASSWORD:Verification Failed: 'Private Key'"),
		[]byte("PASSWORD:Verification Failed: 'Auth'"),
		[]byte("PASSWORD:Verification Failed: 'custom string'"),
	}

	for i, test := range tests {
		event := upgradeEvent(test)

		if passwd, ok := event.(*PasswordEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, passwd)
		}
	}
}

func TestFatalEvent(t *testing.T) {
	tests := [][]byte{
		[]byte("FATAL:"),
	}

	for i, test := range tests {
		event := upgradeEvent(test)

		if fatal, ok := event.(*FatalEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, fatal)
		}
	}
}
