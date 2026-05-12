// SRP authentication is a two-call exchange: InitiateAuth (USER_SRP_AUTH)
// returns a PASSWORD_VERIFIER challenge, and the client follows up with
// RespondToAuthChallenge. The state needed to verify the second call (server
// private exponent `b`, the random salt and secret block we sent, the client's
// SRP_A and the username) must live somewhere across those two calls.
//
// We hold it in an in-memory map keyed by the opaque `Session` UUID we return
// to the client. The TTL matches the authorization-code store: 5 minutes is
// plenty for a tab to receive the challenge and respond.

const SRP_SESSION_TTL_MS = 5 * 60 * 1000;

export interface SrpSessionState {
  username: string;
  // We stash the user's plaintext password here at InitiateAuth time so the
  // RespondToAuthChallenge handler can recompute the verifier without another
  // datastore round-trip. cognito-local already stores plaintext passwords on
  // the user record; this is the same data, scoped to one in-flight exchange.
  password: string;
  salt: Buffer;
  A: bigint;
  B: bigint;
  b: bigint;
  secretBlock: Buffer;
}

export interface SrpSessionStore {
  save(session: string, state: SrpSessionState): void;
  consume(session: string): SrpSessionState | null;
}

interface StoredSession {
  state: SrpSessionState;
  expiresAt: number;
}

export class InMemorySrpSessionStore implements SrpSessionStore {
  private readonly sessions = new Map<string, StoredSession>();

  save(session: string, state: SrpSessionState): void {
    this.sessions.set(session, {
      state,
      expiresAt: Date.now() + SRP_SESSION_TTL_MS,
    });
  }

  consume(session: string): SrpSessionState | null {
    const entry = this.sessions.get(session);
    if (!entry) return null;
    this.sessions.delete(session);
    if (Date.now() > entry.expiresAt) return null;
    return entry.state;
  }
}
