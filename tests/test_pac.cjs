const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {spawnSync} = require('node:child_process');

function load(auto) {
  const code = `from pathfinder.system_proxy import pac_script
print(pac_script({'auto_manage': ${auto ? 'True' : 'False'}, 'proxy_port': 47830, 'services': [{'domains': ['example.com', '*.example.com']}]}))`;
  const result = spawnSync(process.platform === 'win32' ? 'python' : 'python3', ['-c', code], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const context = {dnsDomainIs: (host, domain) => host.endsWith(domain)};
  vm.createContext(context);
  vm.runInContext(result.stdout, context);
  return context.FindProxyForURL;
}

test('all-domain PAC routes public HTTPS through local proxy without direct fallback', () => {
  const route = load(true);
  assert.equal(route('https://example.com/x', 'example.com'), 'PROXY 127.0.0.1:47830');
  assert.equal(route('https://other.org/', 'other.org'), 'PROXY 127.0.0.1:47830');
});

test('PAC leaves local names, literal IPs and unsupported protocols alone', () => {
  const route = load(true);
  for (const host of ['localhost', 'router', 'router.local', 'a.internal', '127.0.0.1', '::1', '1.1.1.1', 'a.onion']) {
    assert.equal(route(`https://${host}/`, host), 'DIRECT', host);
  }
  assert.equal(route('http://example.com/', 'example.com'), 'DIRECT');
  assert.equal(route('wss://example.com/', 'example.com'), 'PROXY 127.0.0.1:47830');
});

test('selected-domain PAC respects domain boundaries', () => {
  const route = load(false);
  for (const host of ['example.com', 'api.example.com', 'nested.api.example.com']) {
    assert.equal(route(`https://${host}/`, host), 'PROXY 127.0.0.1:47830');
  }
  for (const host of ['notexample.com', 'example.com.evil.org', 'other.org']) {
    assert.equal(route(`https://${host}/`, host), 'DIRECT');
  }
});

test('only ru domains bypass the proxy among public domain suffixes', () => {
  const route = load(true);
  for (const host of ['wildberries.ru',
    'www.wildberries.ru', 'wb.ru', 'basket-01.wbbasket.ru', 'gosuslugi.ru',
    'esia.gosuslugi.ru', 'GOSUSLUGI.RU', 'gosuslugi.ru.']) {
    assert.equal(route(`https://${host}/`, host), 'DIRECT', host);
  }
  for (const host of ['vk.com', 'login.vk.com', 'sun1.userapi.com', 'site.su', 'xn--e1afmkfd.xn--p1ai',
    'yastatic.net', 'VK.COM', 'vk.com.', 'fakevk.com', 'vk.com.evil.org', 'gosuslugi.ru.evil.org', 'example.com']) {
    assert.equal(route(`https://${host}/`, host), 'PROXY 127.0.0.1:47830', host);
  }
});
