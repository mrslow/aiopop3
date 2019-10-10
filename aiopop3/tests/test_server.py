import pytest
import poplib

from aiopop3.controller import Controller
from aiopop3.handlers import MemoryHandler
from aiopop3.server import _quote_periods


@pytest.fixture
def server(event_loop):
    handler = MemoryHandler(event_loop)
    user = handler.add_user('user', 'pass')
    user.add_email('email1\r\n\r\nfirst line\r\nsecond line\r\nthird line')
    user.add_email('email2\r\n\r\nsecond text')
    controller = Controller(handler)
    controller.start()
    yield controller
    controller.stop()


class POP3(poplib.POP3):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self.quit()
        finally:
            self.close()


def test_quote_periods():
    assert _quote_periods(b'.') == b'..'


def test_capa(server):
    with POP3(server.hostname, server.port) as client:
        caps = client.capa()
        assert 'SASL' in caps
        assert 'IMPLEMENTATION' in caps
        assert 'RESP-CODES' in caps
        assert 'PIPELINING' in caps
        assert 'LOGIN-DELAY' in caps
        assert 'AUTH-RESP-CODE' in caps
        assert 'EXPIRE' in caps
        assert 'USER' in caps
        assert 'TOP' not in caps
        assert 'UIDL' not in caps
        assert caps['SASL'] == ['PLAIN']


def test_apop(server):
    with POP3(server.hostname, server.port) as client:
        response = client.apop('user', 'pass')
        assert response == b'+OK maildrop locked and ready'
        with pytest.raises(poplib.error_proto) as exc:
            client.apop('user', 'pass')
        assert exc.value.args[0] == b'-ERR Already authenticated'


def test_apop_no_arg(server,):
    with POP3(server.hostname, server.port) as client:
        client._putcmd('APOP')
        response, _ = client._getline()
        assert response == b'-ERR Syntax: APOP <user_name> <password_hash>'


def test_apop_one_arg(server):
    with POP3(server.hostname, server.port) as client:
        client._putcmd('APOP admin')
        response, _ = client._getline()
        assert response == b'-ERR Syntax: APOP <user_name> <password_hash>'


def test_apop_unknown_user(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.apop('foobar', 'pass')
        assert exc.value.args[0] == b'-ERR [AUTH] Invalid password'


def test_apop_invalid_password(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.apop('user', 'foobar')
        assert exc.value.args[0] == b'-ERR [AUTH] Invalid password'


def test_capa_after_auth(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        caps = client.capa()
        assert 'SASL' not in caps
        assert 'IMPLEMENTATION' in caps
        assert 'RESP-CODES' in caps
        assert 'PIPELINING' in caps
        assert 'LOGIN-DELAY' in caps
        assert 'AUTH-RESP-CODE' in caps
        assert 'EXPIRE' in caps
        assert 'USER' not in caps
        assert 'TOP' in caps
        assert 'UIDL' in caps


def test_user(server):
    with POP3(server.hostname, server.port) as client:
        response = client.user('foobar')
        assert response == b'+OK name is a valid mailbox'


def test_no_user(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('USER')
        assert exc.value.args[0] == b'-ERR Syntax: USER <name>'


def test_pass_no_arg(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('PASS')
        assert exc.value.args[0] == b'-ERR Syntax: PASS <password>'


def test_pass_no_user(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.pass_('pass')
        assert exc.value.args[0] == b'-ERR USER command first'


def test_pass(server):
    with POP3(server.hostname, server.port) as client:
        client.user('user')
        msg = client.pass_('pass')
        assert msg == b'+OK maildrop locked and ready'
        with pytest.raises(poplib.error_proto) as exc:
            client.pass_('pass')
        assert exc.value.args[0] == b'-ERR Already authenticated'


def test_pass_unknown_user(server):
    with POP3(server.hostname, server.port) as client:
        client.user('foobar')
        with pytest.raises(poplib.error_proto) as exc:
            client.pass_('pass')
        assert exc.value.args[0] == b'-ERR [AUTH] Invalid password'


def test_pass_invalid_password(server):
    with POP3(server.hostname, server.port) as client:
        client.user('user')
        with pytest.raises(poplib.error_proto) as exc:
            client.pass_('foobar')
        assert exc.value.args[0] == b'-ERR [AUTH] Invalid password'


def test_list_all(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp, msgs, _ = client.list()
        assert resp == b'+OK 2 messages (66 octets)'
        assert msgs == [b'1 45', b'2 21']


def test_list_message(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        response = client.list(1)
        assert response == b'+OK 1 (45 octets)'


def test_list_syntax(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        with pytest.raises(poplib.error_proto) as exc:
            client.list('foobar')
        msg = exc.value.args[0]
        assert msg == b'-ERR Syntax: Message number must be integer'


def test_list_unknown_message(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        with pytest.raises(poplib.error_proto) as exc:
            client.list(3)
        assert exc.value.args[0] == b'-ERR No such message'


def test_list_no_auth(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.list(0)
        assert exc.value.args[0] == b'-ERR Authorization required'


def test_list_dublicate(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        client.list()
        resp, msgs, _ = client.list()
        assert resp == b'+OK 2 messages (66 octets)'
        assert msgs == [b'1 45', b'2 21']


def test_dele_no_auth(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.dele(0)
        assert exc.value.args[0] == b'-ERR Authorization required'


def test_dele_no_arg(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('DELE')
        assert exc.value.args[0] == b'-ERR Syntax: DELE <message_id>'


def test_dele(server):
    user = server.handler.users['user']
    assert len(user.mail_box) == 2
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp = client.dele(2)
        assert resp == b'+OK message deleted'
        assert client.stat() == (1, 45)
        with pytest.raises(poplib.error_proto) as exc:
            client.dele(2)
        assert exc.value.args[0] == b'-ERR no such message'
        assert client.stat() == (1, 45)
    assert len(user.mail_box) == 1


def test_noop(server):
    with POP3(server.hostname, server.port) as client:
        response = client.noop()
        assert response == b'+OK'


def test_noop_with_arg(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('NOOP 1')
        assert exc.value.args[0] == b'-ERR Syntax: NOOP'


def test_rset(server):
    user = server.handler.users['user']
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp = client.dele(1)
        assert resp == b'+OK message deleted'
        resp = client.list()[0]
        assert resp == b'+OK 1 messages (21 octets)'
        resp = client.rset()
        assert resp == b'+OK'
        resp = client.list()[0]
        assert resp == b'+OK 2 messages (66 octets)'
    assert len(user.mail_box) == 2


def test_rset_no_auth(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.rset()
        assert exc.value.args[0] == b'-ERR Authorization required'


def test_stat_no_auth(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.stat()
        assert exc.value.args[0] == b'-ERR Authorization required'


def test_stat_syntax(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('STAT 1')
        assert exc.value.args[0] == b'-ERR Syntax: STAT'


def test_stat(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        count, size = client.stat()
        assert count == 2
        assert size == 66


def test_top_syntax(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('TOP')
        msg = exc.value.args[0]
        assert msg == b'-ERR Syntax: TOP <message_id> <lines_count>'


def test_top_str_lines(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('TOP 1 foo')
        assert exc.value.args[0] == b'-ERR Syntax: Lines count must be integer'


def test_top_no_auth(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.top(1, 1)
        assert exc.value.args[0] == b'-ERR Authorization required'


def test_top(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp, msgs, _ = client.top(1, 1)
        assert resp == b'+OK'
        assert len(msgs) == 4
        assert msgs == [b'email1', b'', b'first line', b'']


def test_retr(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp, msgs, _ = client.retr(1)
        assert resp == b'+OK 45 octets'
        assert len(msgs) == 5
        assert msgs == [b'email1', b'', b'first line', b'second line',
                        b'third line']


def test_quit(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('QUIT 1')
        assert exc.value.args[0] == b'-ERR Syntax: QUIT'


def test_uidl_no_auth(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client.uidl()
        assert exc.value.args[0] == b'-ERR Authorization required'


def test_uidl_no_arg(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp, msgs, _ = client.uidl()
        assert resp == b'+OK'
        assert len(msgs) == 2


def test_uidl(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        resp = client.uidl(1)
        assert resp.startswith(b'+OK 1 ')


def test_auth_no_arg(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('AUTH')
        assert exc.value.args[0] == b'-ERR Unrecognized authentication type'


def test_auth_invalid_arg(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('AUTH KERBEROS_V4')
        msg = exc.value.args[0]
        assert msg == b'-ERR [SYS/PERM] Authentication type not supported'


def test_auth_already_authorized(server):
    with POP3(server.hostname, server.port) as client:
        client.apop('user', 'pass')
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('AUTH PLAIN KwB1c2VyAHBhc3M=')
        assert exc.value.args[0] == b'-ERR Already authenticated'


def test_auth_invalid_password(server):
    with POP3(server.hostname, server.port) as client:
        with pytest.raises(poplib.error_proto) as exc:
            client._shortcmd('AUTH PLAIN KwBhZG1pbgBwYXNz')
        assert exc.value.args[0] == b'-ERR [AUTH] Invalid password'


def test_auth(server):
    with POP3(server.hostname, server.port) as client:
        resp = client._shortcmd('AUTH PLAIN KwB1c2VyAHBhc3M=')
        assert resp == b'+OK PLAIN authentication successful'