import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { scanText } from '../extension/detector.js';
import { fakeChars } from './helpers.js';

function assertClean(text, label = 'text') {
  const result = scanText(text);
  const found = result.findings.map((f) => `line ${f.line}: ${f.category} ${JSON.stringify(text.slice(f.start, f.end))}`);
  assert.deepEqual(found, [], `${label} should have no findings`);
  assert.equal(result.redacted, text, `${label} should be unchanged by redaction`);
}

describe('ordinary code is not flagged', () => {
  test('a React login form', () => {
    assertClean(`
import { useState } from 'react';

export function LoginForm({ onSubmit, apiBase }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const passwordRef = useRef(null);

  async function handleSubmit(event) {
    event.preventDefault();
    if (password.length < 8 || password !== confirmPassword) return;
    const res = await fetch(\`\${apiBase}/login\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: \`Bearer \${token}\` },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    setToken(data.access_token);
    localStorage.setItem('token', data.token);
  }

  return (
    <form onSubmit={handleSubmit}>
      <label htmlFor="password">Password</label>
      <input id="password" type={showPassword ? 'text' : 'password'} value={password}
        autoComplete="current-password" placeholder="Enter your password"
        onChange={(e) => setPassword(e.target.value)} />
      {items.map((item) => <Row key={item.id} token={item.token} />)}
      <button type="submit">Sign in</button>
    </form>
  );
}
`, 'React component');
  });

  test('Node / Express code that handles secrets by reference', () => {
    assertClean(`
const jwt = require('jsonwebtoken');
const config = {
  secret: process.env.SESSION_SECRET,
  apiKey: process.env.API_KEY!,
  password: hashedPassword,
  token: await getToken(),
  dbPassword: config.db.password,
  accessToken: tokens.access,
};
app.post('/login', async (req, res) => {
  const { password } = req.body;
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const password_hash = await bcrypt.hash(password, 10);
  user.password = await bcrypt.hash(password, 12);
  if (!token) throw new Error('Invalid token: missing');
  console.log("Enter password: ", prompt);
  res.json({ token, token_type: "Bearer", expires_in: 3600 });
});
`, 'Express handler');
  });

  test('TypeScript types and schemas', () => {
    assertClean(`
interface User {
  password: string;
  token?: string | null;
  apiKey: string | undefined;
}
type Session = { secret: Buffer; refreshToken: string };
const schema = z.object({ password: z.string().min(8), token: z.string() });
const userSchema = new Schema({ password: { type: String, required: true, select: false } });
let password: string = undefined;
`, 'TypeScript');
  });

  test('Python', () => {
    assertClean(`
def connect(user, password=None, token=None):
    password = os.environ["DB_PASSWORD"]
    token = os.getenv("API_TOKEN")
    secret_key = settings.SECRET_KEY
    conn = psycopg2.connect(user=user, password=password, host=host)
    api_key: str = get_api_key()
    password = getpass.getpass("Password: ")
    return Client(api_key=api_key, token=token)

class User(models.Model):
    password = models.CharField(max_length=128)
`, 'Python');
  });

  test('configuration that references secrets instead of containing them', () => {
    assertClean(`
DB_PASSWORD=
API_KEY=your_api_key_here
OPENAI_API_KEY=<your-openai-key>
STRIPE_SECRET_KEY=not-a-real-stripe-test-keyx
GITHUB_TOKEN=\${GITHUB_TOKEN}
export TOKEN=$(gh auth token)
PASSWORD="$1"
SECRET_KEY=changeme
password: "{{ vault_db_password }}"
token: \${{ secrets.GITHUB_TOKEN }}
spring.datasource.password=\${DB_PASSWORD}
DATABASE_URL=postgres://user:password@localhost:5432/app
DATABASE_URL=postgresql://\${DB_USER}:\${DB_PASS}@\${DB_HOST}/app
GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/service-account.json
SSL_CLIENT_KEY=./certs/client.key
PWD=/Users/dev/project
OLDPWD=/Users/dev
`, 'templated config');
  });

  test('ML / tokenizer configuration', () => {
    assertClean(`
{"max_tokens": 1024, "eos_token": "</s>", "bos_token": "<s>", "pad_token": "[PAD]",
 "unk_token": "<unk>", "mask_token": "<mask>", "tokenizer_class": "LlamaTokenizer",
 "stop_token": "###", "num_tokens": 32000}
`, 'tokenizer config');
  });

  test('i18n strings and validation messages', () => {
    assertClean(`
{
  "password": "Password",
  "forgotPassword": "Forgot your password?",
  "passwordTooShort": "Password must be at least 8 characters",
  "resetPassword": "Passwort zurücksetzen",
  "token": "Token",
  "secret": "Mot de passe secret"
}
errors.password = "Too short";
`, 'i18n');
  });

  test('Markdown documentation about credential flags', () => {
    assertClean(`
| Command-line credentials | \`curl -u user:pass\`, \`mysql -pPASSWORD\`, \`--password …\`, \`--api-key=<value>\` |
Pass credentials with \`curl -u user:password\` or \`--token $TOKEN\`, never inline.
`, 'Markdown docs');
  });

  test('shell sessions', () => {
    assertClean(`
$ git push -u origin main
$ docker run -u 1000:1000 -v $PWD:/app node:22
$ read -s PASSWORD
$ echo "token: $TOKEN"
$ docker login --password-stdin < token.txt
$ kubectl get secret db-password -o yaml
$ ssh git@github.com
`, 'shell');
  });
});

describe('ordinary text and URLs are unchanged', () => {
  test('URLs with query strings, ports and fragments', () => {
    assertClean([
      'https://example.com/docs?page=2&sort=asc#install',
      'http://localhost:3000/api/users?limit=50',
      'https://github.com/org/repo/blob/main/src/password-reset.ts#L42',
      'ssh://git@github.com:22/org/repo.git',
      'https://example.com/search?q=token&lang=en',
      'ftp://files.example.com:21/pub/README',
      'https://example.com:8443/path@v2/assets',
    ].join('\n'), 'URLs');
  });

  test('prose about secrets', () => {
    assertClean(`
Never commit your password or API key to Git. Rotate any token that leaks.
Bearer authentication sends a bearer token in the Authorization header.
The secret: use environment variables. A JWT has three parts separated by dots.
Set the token in your shell, e.g. Bearer <token>, and keep it out of logs.
`, 'prose');
  });

  test('hashes, UUIDs, colors and other high-entropy data that are not secrets', () => {
    assertClean(`
commit 9fceb02d0ae598e95dc970b74767f19372d61af8
id: 3f2504e0-4f89-11d3-9a0c-0305e82c3301
integrity: sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==
color: #1f2937;
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==
sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
`, 'non-secret data');
  });

  test('public keys, certificates and JSX components', () => {
    assertClean(`
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${fakeChars(43, 70)} dev@laptop
<Password>Enter</Password>
<Token value={token} />
`, 'public material');
  });
});
