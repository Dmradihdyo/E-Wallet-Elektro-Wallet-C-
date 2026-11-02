#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX // cegah makro min/max milik windows.h bentrok dengan std::max
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#endif

#include <iostream>
#include <atomic>
#include <random>
#include <cstdint>
#include <cstdlib>
#include <csignal>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <cmath>
#include <cstring>

// ============================================================================
// 1. DUKUNGAN LINTAS PLATFORM (WINDOWS / LINUX / MACOS) - SOCKET & TERMINAL
// ============================================================================
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
void clearScreen() { system("cls"); }
char customGetch() { return _getch(); }
void enableVTMode()
{
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD dwMode = 0;
  GetConsoleMode(hOut, &dwMode);
  dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
  SetConsoleMode(hOut, dwMode);
}
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <termios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/time.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
void clearScreen() { system("clear"); }
void enableVTMode() {}
char customGetch()
{
  char buf = 0;
  struct termios old = {0};
  if (tcgetattr(0, &old) < 0)
    return 0;
  old.c_lflag &= ~ICANON;
  old.c_lflag &= ~ECHO;
  old.c_cc[VMIN] = 1;
  old.c_cc[VTIME] = 0;
  tcsetattr(0, TCSANOW, &old);
  if (read(0, &buf, 1) < 0)
    buf = 0;
  old.c_lflag |= ICANON;
  old.c_lflag |= ECHO;
  tcsetattr(0, TCSADRAIN, &old);
  return buf;
}
#endif

std::mutex dbMutex;

// ============================================================================
// 2. DETEKSI IP LAN LAPTOP (ALAMAT YANG DITANAMKAN KE DALAM URL QR CODE)
// ============================================================================
// Alamat loopback (127.0.0.1 / localhost) TIDAK PERNAH dipakai di QR Code:
// HP akan mengartikannya sebagai HP itu sendiri, bukan laptop.
std::string g_manualHostIP = ""; // diisi dari environment EWALLET_HOST_IP atau menu QR

int getConfiguredPort()
{
  const char *env = std::getenv("EWALLET_PORT");
  if (env)
  {
    int p = std::atoi(env);
    if (p >= 1024 && p <= 65535)
      return p;
  }
  return 8080;
}

void setSocketTimeout(SOCKET s, int seconds)
{
#ifdef _WIN32
  DWORD ms = static_cast<DWORD>(seconds * 1000);
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
#else
  struct timeval tv;
  tv.tv_sec = seconds;
  tv.tv_usec = 0;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif
}

bool parseIPv4(const std::string &ip, int o[4])
{
  int a, b, c, d;
  char extra;
  if (sscanf(ip.c_str(), "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4)
    return false;
  if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
    return false;
  o[0] = a;
  o[1] = b;
  o[2] = c;
  o[3] = d;
  return true;
}

bool isValidIPv4(const std::string &ip)
{
  int o[4];
  return parseIPv4(ip, o);
}

// true jika alamat tidak boleh dipakai di QR (loopback, 0.0.0.0, APIPA, multicast)
bool isLoopbackOrUnusable(const std::string &ip)
{
  int o[4];
  if (!parseIPv4(ip, o))
    return true;
  if (o[0] == 127 || o[0] == 0)
    return true;
  if (o[0] == 169 && o[1] == 254)
    return true;
  if (o[0] >= 224)
    return true;
  return false;
}

// Urutan prioritas: LAN rumahan/hotspot lebih baik daripada adaptor virtual
int ipRank(const std::string &ip)
{
  int o[4];
  if (!parseIPv4(ip, o))
    return 99;
  if (o[0] == 192 && o[1] == 168 && (o[2] == 56 || o[2] == 99))
    return 8; // VirtualBox / docker-machine
  if (o[0] == 172 && o[1] == 17)
    return 8; // docker0
  if (o[0] == 192 && o[1] == 168)
    return 1;
  if (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
    return 2;
  if (o[0] == 10)
    return 3;
  return 5;
}

// IP interface yang dipakai untuk rute keluar (UDP connect tidak mengirim paket)
std::string detectRouteIP()
{
  std::string result = "";
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return result;
#endif
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock != INVALID_SOCKET)
  {
    sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr("8.8.8.8");
    remote.sin_port = htons(53);

    if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) != SOCKET_ERROR)
    {
      sockaddr_in name;
      socklen_t namelen = sizeof(name);
      if (getsockname(sock, (struct sockaddr *)&name, &namelen) != SOCKET_ERROR)
      {
        char *ip = inet_ntoa(name.sin_addr);
        if (ip)
          result = std::string(ip);
      }
    }
    closesocket(sock);
  }
#ifdef _WIN32
  WSACleanup();
#endif
  return result;
}

// Semua alamat IPv4 aktif di laptop (tanpa loopback), diurutkan dari yang terbaik
std::vector<std::string> getLocalIPCandidates()
{
  std::vector<std::string> out;
  auto add = [&](const std::string &ip)
  {
    if (!isLoopbackOrUnusable(ip) && std::find(out.begin(), out.end(), ip) == out.end())
      out.push_back(ip);
  };

#ifdef _WIN32
  WSADATA wsaData;
  bool started = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
  char host[256];
  if (started && gethostname(host, sizeof(host)) == 0)
  {
    hostent *he = gethostbyname(host);
    if (he && he->h_addrtype == AF_INET)
    {
      for (char **p = he->h_addr_list; *p != nullptr; ++p)
      {
        in_addr a;
        memcpy(&a, *p, sizeof(a));
        add(inet_ntoa(a));
      }
    }
  }
  if (started)
    WSACleanup();
#else
  struct ifaddrs *ifs = nullptr;
  if (getifaddrs(&ifs) == 0)
  {
    for (struct ifaddrs *i = ifs; i != nullptr; i = i->ifa_next)
    {
      if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
        continue;
      if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK))
        continue;
      std::string name = i->ifa_name ? i->ifa_name : "";
      const char *skip[] = {"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "tun", "utun", "awdl", "llw", "lo"};
      bool isVirtual = false;
      for (const char *pre : skip)
        if (name.compare(0, strlen(pre), pre) == 0)
          isVirtual = true;
      if (isVirtual)
        continue;
      char buf[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, buf, sizeof(buf)))
        add(buf);
    }
    freeifaddrs(ifs);
  }
#endif
  std::stable_sort(out.begin(), out.end(), [](const std::string &a, const std::string &b)
                   { return ipRank(a) < ipRank(b); });
  return out;
}

// IP yang dipakai di QR Code. Mengembalikan "" jika tidak ada IP LAN yang valid
// (sengaja TIDAK jatuh ke 127.0.0.1).
std::string getLocalIPAddress()
{
  if (!g_manualHostIP.empty())
    return g_manualHostIP;

  std::string routeIP = detectRouteIP();
  if (!routeIP.empty() && !isLoopbackOrUnusable(routeIP) && ipRank(routeIP) < 8)
    return routeIP;

  std::vector<std::string> cands = getLocalIPCandidates();
  if (!cands.empty())
    return cands.front();

  if (!routeIP.empty() && !isLoopbackOrUnusable(routeIP))
    return routeIP;
  return "";
}

// ============================================================================
// 3. GENERATOR QR CODE ISO/IEC 18004 (Byte mode, ECC Level L, Versi 1-9)
//    - Reed-Solomon + interleaving blok, 8 mask + penalty, format & version info
// ============================================================================
class SimpleQRGenerator
{
private:
  static uint8_t gfMul(uint8_t a, uint8_t b)
  {
    unsigned r = 0, x = a;
    for (int i = 0; i < 8; i++)
    {
      if ((b >> i) & 1)
        r ^= x;
      x <<= 1;
      if (x & 0x100)
        x ^= 0x11D;
    }
    return static_cast<uint8_t>(r);
  }

  static std::vector<uint8_t> rsGenerator(int degree)
  {
    std::vector<uint8_t> g(degree, 0);
    g[degree - 1] = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; i++)
    {
      for (int j = 0; j < degree; j++)
      {
        g[j] = gfMul(g[j], root);
        if (j + 1 < degree)
          g[j] ^= g[j + 1];
      }
      root = gfMul(root, 0x02);
    }
    return g;
  }

  static std::vector<uint8_t> rsRemainder(const std::vector<uint8_t> &data, const std::vector<uint8_t> &gen)
  {
    std::vector<uint8_t> res(gen.size(), 0);
    for (uint8_t b : data)
    {
      uint8_t factor = b ^ res[0];
      res.erase(res.begin());
      res.push_back(0);
      for (size_t i = 0; i < gen.size(); i++)
        res[i] ^= gfMul(gen[i], factor);
    }
    return res;
  }

  // Tabel Level L untuk versi 1..9 (indeks = versi)
  static int totalCodewords(int v)
  {
    static const int t[] = {0, 26, 44, 70, 100, 134, 172, 196, 242, 292};
    return t[v];
  }
  static int eccPerBlock(int v)
  {
    static const int t[] = {0, 7, 10, 15, 20, 26, 18, 20, 24, 30};
    return t[v];
  }
  static int numBlocks(int v)
  {
    static const int t[] = {0, 1, 1, 1, 1, 1, 2, 2, 2, 2};
    return t[v];
  }
  static std::vector<int> alignPos(int v)
  {
    static const std::vector<std::vector<int>> t = {
        {}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}};
    return t[v];
  }

  struct Matrix
  {
    int size;
    std::vector<std::vector<bool>> mod;
    std::vector<std::vector<bool>> fn; // function module?
    explicit Matrix(int s) : size(s), mod(s, std::vector<bool>(s, false)), fn(s, std::vector<bool>(s, false)) {}
    void setFn(int r, int c, bool dark)
    {
      if (r < 0 || c < 0 || r >= size || c >= size)
        return;
      mod[r][c] = dark;
      fn[r][c] = true;
    }
  };

  static void drawFunctionPatterns(Matrix &m, int ver)
  {
    int n = m.size;
    for (int i = 0; i < n; i++)
    {
      m.setFn(6, i, i % 2 == 0);
      m.setFn(i, 6, i % 2 == 0);
    }
    auto finder = [&](int cr, int cc)
    {
      for (int dr = -4; dr <= 4; dr++)
        for (int dc = -4; dc <= 4; dc++)
        {
          int d = std::max(std::abs(dr), std::abs(dc));
          m.setFn(cr + dr, cc + dc, d != 2 && d != 4);
        }
    };
    finder(3, 3);
    finder(3, n - 4);
    finder(n - 4, 3);

    std::vector<int> ap = alignPos(ver);
    int na = static_cast<int>(ap.size());
    for (int i = 0; i < na; i++)
      for (int j = 0; j < na; j++)
      {
        if ((i == 0 && j == 0) || (i == 0 && j == na - 1) || (i == na - 1 && j == 0))
          continue;
        for (int dr = -2; dr <= 2; dr++)
          for (int dc = -2; dc <= 2; dc++)
            m.setFn(ap[i] + dr, ap[j] + dc, std::max(std::abs(dr), std::abs(dc)) != 1);
      }

    drawFormatBits(m, 0); // reservasi area format
    if (ver >= 7)
    {
      int rem = ver;
      for (int i = 0; i < 12; i++)
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
      long bits = (static_cast<long>(ver) << 12) | rem;
      for (int i = 0; i < 18; i++)
      {
        bool bit = ((bits >> i) & 1) != 0;
        int a = n - 11 + i % 3, b = i / 3;
        m.setFn(a, b, bit);
        m.setFn(b, a, bit);
      }
    }
  }

  static void drawFormatBits(Matrix &m, int mask)
  {
    int n = m.size;
    int data = (1 << 3) | mask; // ECC level L = 01, lalu 3 bit mask
    int rem = data;
    for (int i = 0; i < 10; i++)
      rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    int bits = ((data << 10) | rem) ^ 0x5412;

    for (int i = 0; i <= 5; i++)
      m.setFn(i, 8, ((bits >> i) & 1) != 0);
    m.setFn(7, 8, ((bits >> 6) & 1) != 0);
    m.setFn(8, 8, ((bits >> 7) & 1) != 0);
    m.setFn(8, 7, ((bits >> 8) & 1) != 0);
    for (int i = 9; i < 15; i++)
      m.setFn(8, 14 - i, ((bits >> i) & 1) != 0);

    for (int i = 0; i < 8; i++)
      m.setFn(8, n - 1 - i, ((bits >> i) & 1) != 0);
    for (int i = 8; i < 15; i++)
      m.setFn(n - 15 + i, 8, ((bits >> i) & 1) != 0);
    m.setFn(n - 8, 8, true); // dark module
  }

  static void placeData(Matrix &m, const std::vector<uint8_t> &cw)
  {
    int n = m.size;
    size_t i = 0;
    for (int right = n - 1; right >= 1; right -= 2)
    {
      if (right == 6)
        right = 5;
      for (int vert = 0; vert < n; vert++)
        for (int j = 0; j < 2; j++)
        {
          int x = right - j;
          bool upward = ((right + 1) & 2) == 0;
          int y = upward ? n - 1 - vert : vert;
          if (!m.fn[y][x] && i < cw.size() * 8)
          {
            m.mod[y][x] = ((cw[i >> 3] >> (7 - (i & 7))) & 1) != 0;
            i++;
          }
        }
    }
  }

  static void applyMask(Matrix &m, int mask)
  {
    int n = m.size;
    for (int y = 0; y < n; y++)
      for (int x = 0; x < n; x++)
      {
        bool inv = false;
        switch (mask)
        {
        case 0:
          inv = (x + y) % 2 == 0;
          break;
        case 1:
          inv = y % 2 == 0;
          break;
        case 2:
          inv = x % 3 == 0;
          break;
        case 3:
          inv = (x + y) % 3 == 0;
          break;
        case 4:
          inv = (x / 3 + y / 2) % 2 == 0;
          break;
        case 5:
          inv = x * y % 2 + x * y % 3 == 0;
          break;
        case 6:
          inv = (x * y % 2 + x * y % 3) % 2 == 0;
          break;
        case 7:
          inv = ((x + y) % 2 + x * y % 3) % 2 == 0;
          break;
        }
        if (!m.fn[y][x] && inv)
          m.mod[y][x] = !m.mod[y][x];
      }
  }

  static int penalty(const Matrix &m)
  {
    int n = m.size, p = 0;
    // N1: deretan modul sewarna (>=5) pada baris & kolom
    // N3: pola mirip finder (1:1:3:1:1 + 4 modul terang) pada baris & kolom
    for (int pass = 0; pass < 2; pass++)
    {
      for (int a = 0; a < n; a++)
      {
        int run = 1;
        unsigned win = 0;
        for (int b = 0; b < n; b++)
        {
          bool cur = pass ? m.mod[b][a] : m.mod[a][b];
          if (b > 0)
          {
            bool prv = pass ? m.mod[b - 1][a] : m.mod[a][b - 1];
            if (cur == prv)
            {
              run++;
              if (run == 5)
                p += 3;
              else if (run > 5)
                p++;
            }
            else
              run = 1;
          }
          win = ((win << 1) | (cur ? 1u : 0u)) & 0x7FF;
          if (b >= 10 && (win == 0x05D || win == 0x5D0))
            p += 40; // 00001011101 atau 10111010000
        }
      }
    }
    // N2: blok 2x2 sewarna
    for (int y = 0; y + 1 < n; y++)
      for (int x = 0; x + 1 < n; x++)
      {
        bool c = m.mod[y][x];
        if (c == m.mod[y][x + 1] && c == m.mod[y + 1][x] && c == m.mod[y + 1][x + 1])
          p += 3;
      }
    // N4: keseimbangan modul gelap
    int dark = 0, total = n * n;
    for (int y = 0; y < n; y++)
      for (int x = 0; x < n; x++)
        if (m.mod[y][x])
          dark++;
    int k = (std::abs(dark * 20 - total * 10) + total - 1) / total - 1;
    if (k > 0)
      p += k * 10;
    return p;
  }

public:
  // Mengembalikan matriks modul (true = hitam). Kosong jika data terlalu panjang.
  static std::vector<std::vector<bool>> generateQR(const std::string &text)
  {
    int ver = 0;
    for (int v = 1; v <= 9; v++)
    {
      int dataCw = totalCodewords(v) - eccPerBlock(v) * numBlocks(v);
      size_t need = (4 + 8 + text.size() * 8 + 7) / 8;
      if (need <= static_cast<size_t>(dataCw))
      {
        ver = v;
        break;
      }
    }
    if (ver == 0)
      return {};

    int dataCw = totalCodewords(ver) - eccPerBlock(ver) * numBlocks(ver);
    std::vector<uint8_t> bits;
    auto put = [&](uint32_t val, int len)
    {
      for (int i = len - 1; i >= 0; i--)
        bits.push_back((val >> i) & 1);
    };
    put(0x4, 4);
    put(static_cast<uint32_t>(text.size()), 8);
    for (unsigned char c : text)
      put(c, 8);
    size_t capBits = static_cast<size_t>(dataCw) * 8;
    for (int i = 0; i < 4 && bits.size() < capBits; i++)
      bits.push_back(0);
    while (bits.size() % 8 != 0)
      bits.push_back(0);

    std::vector<uint8_t> data;
    for (size_t i = 0; i < bits.size(); i += 8)
    {
      uint8_t b = 0;
      for (int j = 0; j < 8; j++)
        b = static_cast<uint8_t>((b << 1) | bits[i + j]);
      data.push_back(b);
    }
    for (uint8_t pad = 0xEC; data.size() < static_cast<size_t>(dataCw); pad ^= (0xEC ^ 0x11))
      data.push_back(pad);

    // Bagi ke blok, hitung ECC, lalu interleave
    int nb = numBlocks(ver), ecl = eccPerBlock(ver);
    int shortLen = dataCw / nb, longBlocks = dataCw % nb;
    std::vector<uint8_t> gen = rsGenerator(ecl);
    std::vector<std::vector<uint8_t>> blocks, eccs;
    size_t k = 0;
    for (int b = 0; b < nb; b++)
    {
      int len = shortLen + (b >= nb - longBlocks ? 1 : 0);
      std::vector<uint8_t> blk(data.begin() + k, data.begin() + k + len);
      k += len;
      eccs.push_back(rsRemainder(blk, gen));
      blocks.push_back(blk);
    }
    std::vector<uint8_t> all;
    for (int i = 0; i <= shortLen; i++)
      for (int b = 0; b < nb; b++)
        if (i < static_cast<int>(blocks[b].size()))
          all.push_back(blocks[b][i]);
    for (int i = 0; i < ecl; i++)
      for (int b = 0; b < nb; b++)
        all.push_back(eccs[b][i]);

    int size = ver * 4 + 17;
    Matrix base(size);
    drawFunctionPatterns(base, ver);
    placeData(base, all);

    int bestMask = 0, bestPen = 1 << 30;
    Matrix best = base;
    for (int mask = 0; mask < 8; mask++)
    {
      Matrix t = base;
      applyMask(t, mask);
      drawFormatBits(t, mask);
      int p = penalty(t);
      if (p < bestPen)
      {
        bestPen = p;
        bestMask = mask;
        best = t;
      }
    }
    (void)bestMask;
    return best.mod;
  }

  // Render ke konsol (kontras tinggi: putih terang & hitam, quiet zone 4 modul)
  static void printToConsole(const std::string &text)
  {
    enableVTMode();
    auto qr = generateQR(text);
    if (qr.empty())
    {
      std::cout << "[ERROR] URL terlalu panjang untuk QR Code (maks. ~190 karakter).\n";
      return;
    }
    int size = static_cast<int>(qr.size());
    const int quiet = 4;
    const char *W = "\033[107m  \033[0m";
    const char *B = "\033[40m  \033[0m";
    std::cout << "\n";
    for (int r = -quiet; r < size + quiet; r++)
    {
      for (int c = -quiet; c < size + quiet; c++)
      {
        bool dark = (r >= 0 && c >= 0 && r < size && c < size) && qr[r][c];
        std::cout << (dark ? B : W);
      }
      std::cout << "\n";
    }
    std::cout << "\033[0m\n";
  }

  // SVG vektor (tajam di ukuran berapa pun) untuk ditampilkan di browser laptop
  static std::string toSvg(const std::string &text, int pixelPerModule = 10)
  {
    auto qr = generateQR(text);
    if (qr.empty())
      return "";
    int size = static_cast<int>(qr.size());
    const int quiet = 4;
    int total = size + quiet * 2;
    std::stringstream ss;
    ss << "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 " << total << " " << total
       << "' width='" << total * pixelPerModule << "' height='" << total * pixelPerModule
       << "' shape-rendering='crispEdges'><rect width='100%' height='100%' fill='#ffffff'/><path fill='#000000' d='";
    for (int r = 0; r < size; r++)
      for (int c = 0; c < size; c++)
        if (qr[r][c])
          ss << "M" << (c + quiet) << "," << (r + quiet) << "h1v1h-1z";
    ss << "'/></svg>";
    return ss.str();
  }
};

// ============================================================================
// 4. HELPER & VALIDASI DATA
// ============================================================================
std::string getMaskedInput(const std::string &prompt)
{
  std::cout << prompt << std::flush; // flush: tombol dibaca langsung (tanpa buffer cin)
  std::string input = "";
  char ch;
  while (true)
  {
    ch = customGetch();
    if (ch == 13 || ch == 10)
    {
      std::cout << std::endl;
      break;
    }
    else if (ch == 8 || ch == 127)
    {
      if (!input.empty())
      {
        input.pop_back();
        std::cout << "\b \b";
      }
    }
    else if (ch >= 32 && ch <= 126)
    {
      input.push_back(ch);
      std::cout << '*';
    }
  }
  return input;
}

std::string hashSecurity(const std::string &rawText)
{
  unsigned long long hash = 14695981039346656037ULL;
  std::string salted = rawText + "ELEKTRO_WALLET_SALT_SECURE_2026";
  for (char c : salted)
  {
    hash ^= static_cast<unsigned char>(c);
    hash *= 1099511628211ULL;
  }
  std::stringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(16) << hash;
  return ss.str();
}

bool isValidPassword(const std::string &pass)
{
  if (pass.length() < 8)
    return false;
  bool hasUpper = false, hasLower = false, hasDigit = false;
  for (char c : pass)
  {
    if (std::isupper(static_cast<unsigned char>(c)))
      hasUpper = true;
    if (std::islower(static_cast<unsigned char>(c)))
      hasLower = true;
    if (std::isdigit(static_cast<unsigned char>(c)))
      hasDigit = true;
  }
  return hasUpper && hasLower && hasDigit;
}

bool isValidPin(const std::string &pin)
{
  if (pin.length() != 6)
    return false;
  for (char c : pin)
  {
    if (!std::isdigit(static_cast<unsigned char>(c)))
      return false;
  }
  return true;
}

double stringToDouble(const std::string &str)
{
  if (str.empty())
    return 0.0;
  std::stringstream ss(str);
  double val = 0.0;
  ss >> val;
  return val;
}

int stringToInt(const std::string &str)
{
  if (str.empty())
    return 0;
  std::stringstream ss(str);
  int val = 0;
  ss >> val;
  return val;
}

std::string getCurrentTimestamp()
{
  std::time_t now = std::time(nullptr);
  char buf[80];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
  return std::string(buf);
}

std::string formatRupiah(double amount)
{
  std::stringstream ss;
  ss << "Rp " << std::fixed << std::setprecision(2) << amount;
  return ss.str();
}

void pauseConsole()
{
  std::cout << "\nTekan [ENTER] untuk melanjutkan...";
  std::cin.ignore(10000, '\n');
  std::cin.get();
}

int hexDigitValue(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

std::string urlDecode(const std::string &str)
{
  std::string ret;
  for (size_t i = 0; i < str.length(); i++)
  {
    if (str[i] == '%' && i + 2 < str.length() && hexDigitValue(str[i + 1]) >= 0 && hexDigitValue(str[i + 2]) >= 0)
    {
      ret += static_cast<char>(hexDigitValue(str[i + 1]) * 16 + hexDigitValue(str[i + 2]));
      i += 2;
    }
    else if (str[i] == '+')
    {
      ret += ' ';
    }
    else
    {
      ret += str[i];
    }
  }
  return ret;
}

// Percent-encoding agar User ID dengan karakter khusus (& # ? spasi) tidak merusak URL
std::string urlEncode(const std::string &s)
{
  static const char *hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : s)
  {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
      out += static_cast<char>(c);
    else
    {
      out += '%';
      out += hex[c >> 4];
      out += hex[c & 15];
    }
  }
  return out;
}

// Mencegah HTML injection dari nama/ID pengguna pada halaman web
std::string htmlEscape(const std::string &s)
{
  std::string out;
  for (char c : s)
  {
    switch (c)
    {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    case '\'':
      out += "&#39;";
      break;
    default:
      out += c;
    }
  }
  return out;
}

std::string toLowerStr(std::string s)
{
  for (auto &c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// URL lengkap halaman pembayaran yang ditanam ke QR Code.
// Contoh: http://192.168.1.10:8080/payment?merchant=USER001
std::string buildPaymentUrl(const std::string &host, int port, const std::string &userId)
{
  return "http://" + host + ":" + std::to_string(port) + "/payment?merchant=" + urlEncode(userId);
}

std::map<std::string, std::string> parseUrlFormData(const std::string &body)
{
  std::map<std::string, std::string> data;
  std::stringstream ss(body);
  std::string item;
  while (std::getline(ss, item, '&'))
  {
    size_t pos = item.find('=');
    if (pos != std::string::npos)
    {
      std::string key = urlDecode(item.substr(0, pos));
      std::string val = urlDecode(item.substr(pos + 1));
      data[key] = val;
    }
  }
  return data;
}

std::string getQueryParam(const std::string &url, const std::string &param)
{
  size_t pos = url.find('?');
  if (pos == std::string::npos)
    return "";
  std::string query = url.substr(pos + 1);
  std::stringstream ss(query);
  std::string item;
  while (std::getline(ss, item, '&'))
  {
    size_t eqPos = item.find('=');
    if (eqPos != std::string::npos)
    {
      std::string key = urlDecode(item.substr(0, eqPos));
      std::string val = urlDecode(item.substr(eqPos + 1));
      if (key == param)
        return val;
    }
  }
  return "";
}

// Tes mandiri: apakah web server menjawab lewat alamat LAN (bukan loopback)?
// Catatan: tes ini berjalan di laptop sendiri, jadi TIDAK bisa membuktikan firewall
// mengizinkan perangkat lain; itu harus diuji dari HP.
bool selfTestHttp(const std::string &ip, int port, std::string &detail)
{
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
  bool ok = false;
  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET)
  {
    detail = "gagal membuat socket";
  }
  else
  {
    setSocketTimeout(s, 3);
    sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<unsigned short>(port));
    a.sin_addr.s_addr = inet_addr(ip.c_str());
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR)
    {
      detail = "tidak dapat terhubung ke " + ip + ":" + std::to_string(port);
    }
    else
    {
      std::string req = "GET /health HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n";
      send(s, req.c_str(), static_cast<int>(req.size()), 0);
      std::string resp;
      char buf[512];
      int n;
      while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
        resp.append(buf, static_cast<size_t>(n));
      if (resp.find("200 OK") != std::string::npos)
      {
        ok = true;
        detail = "server menjawab HTTP 200 di " + ip + ":" + std::to_string(port);
      }
      else
      {
        detail = "tersambung, tetapi jawaban bukan HTTP 200";
      }
    }
    closesocket(s);
  }
#ifdef _WIN32
  WSACleanup();
#endif
  return ok;
}

// ============================================================================
// 5. STRUCT MODEL DATA & PERSISTENSI DATABASE
// ============================================================================
struct User
{
  std::string id;
  std::string name;
  std::string email;
  std::string passwordHash;
  std::string pinHash;
  double balance;
  std::string status;
  std::string createdAt;

  std::string serialize() const
  {
    std::stringstream ss;
    // fixed + 2 desimal: tanpa ini saldo >= 1.000.000 tersimpan sebagai "1.23457e+06"
    // dan kehilangan presisi saat dibaca kembali dari users.txt
    ss << id << "|" << name << "|" << email << "|" << passwordHash << "|"
       << pinHash << "|" << std::fixed << std::setprecision(2) << balance << "|" << status << "|" << createdAt;
    return ss.str();
  }

  static User deserialize(const std::string &line)
  {
    User u;
    std::stringstream ss(line);
    std::string token;

    std::getline(ss, u.id, '|');
    std::getline(ss, u.name, '|');
    std::getline(ss, u.email, '|');
    std::getline(ss, u.passwordHash, '|');
    std::getline(ss, u.pinHash, '|');
    std::getline(ss, token, '|');
    u.balance = stringToDouble(token);
    std::getline(ss, u.status, '|');
    std::getline(ss, u.createdAt, '|');
    return u;
  }
};

struct Transaction
{
  int trxId;
  std::string userId;
  std::string type;
  double amount;
  std::string targetId;
  std::string timestamp;
  std::string status;

  std::string serialize() const
  {
    std::stringstream ss;
    ss << trxId << "|" << userId << "|" << type << "|" << std::fixed << std::setprecision(2) << amount << "|"
       << targetId << "|" << timestamp << "|" << status;
    return ss.str();
  }

  static Transaction deserialize(const std::string &line)
  {
    Transaction t;
    std::stringstream ss(line);
    std::string token;

    std::getline(ss, token, '|');
    t.trxId = stringToInt(token);
    std::getline(ss, t.userId, '|');
    std::getline(ss, t.type, '|');
    std::getline(ss, token, '|');
    t.amount = stringToDouble(token);
    std::getline(ss, t.targetId, '|');
    std::getline(ss, t.timestamp, '|');
    std::getline(ss, t.status, '|');
    if (t.status.empty())
      t.status = "BERHASIL";
    return t;
  }
};

class DatabaseManager
{
private:
  std::string userFile;
  std::string trxFile;
  std::vector<User> users;
  std::vector<Transaction> transactions;
  int nextTrxId;

  void loadUsersInternal()
  {
    users.clear();
    std::ifstream file(userFile);
    if (!file.is_open())
      return;
    std::string line;
    while (std::getline(file, line))
    {
      if (!line.empty())
      {
        users.push_back(User::deserialize(line));
      }
    }
    file.close();
  }

  void loadTransactionsInternal()
  {
    transactions.clear();
    nextTrxId = 1001;
    std::ifstream file(trxFile);
    if (!file.is_open())
      return;
    std::string line;
    while (std::getline(file, line))
    {
      if (!line.empty())
      {
        Transaction t = Transaction::deserialize(line);
        transactions.push_back(t);
        if (t.trxId >= nextTrxId)
        {
          nextTrxId = t.trxId + 1;
        }
      }
    }
    file.close();
  }

  void saveUsersInternal()
  {
    std::ofstream file(userFile, std::ios::trunc);
    for (const auto &u : users)
    {
      file << u.serialize() << "\n";
    }
    file.close();
  }

  void saveTransactionsInternal()
  {
    std::ofstream file(trxFile, std::ios::trunc);
    for (const auto &t : transactions)
    {
      file << t.serialize() << "\n";
    }
    file.close();
  }

public:
  DatabaseManager(std::string uF = "users.txt", std::string tF = "transactions.txt")
      : userFile(uF), trxFile(tF), nextTrxId(1001)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    loadUsersInternal();
    loadTransactionsInternal();
  }

  bool existsUser(const std::string &id)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    for (const auto &u : users)
    {
      if (u.id == id)
        return true;
    }
    return false;
  }

  bool existsEmail(const std::string &email)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    for (const auto &u : users)
    {
      if (u.email == email)
        return true;
    }
    return false;
  }

  bool addUser(const User &u)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    for (const auto &existing : users)
    {
      if (existing.id == u.id)
        return false;
    }
    users.push_back(u);
    saveUsersInternal();
    return true;
  }

  User getUserCopy(const std::string &id)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    for (const auto &u : users)
    {
      if (u.id == id)
        return u;
    }
    return User();
  }

  void updatePassword(const std::string &id, const std::string &newHash)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    for (auto &u : users)
    {
      if (u.id == id)
      {
        u.passwordHash = newHash;
        break;
      }
    }
    saveUsersInternal();
  }

  void updatePin(const std::string &id, const std::string &newPinHash)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    for (auto &u : users)
    {
      if (u.id == id)
      {
        u.pinHash = newPinHash;
        break;
      }
    }
    saveUsersInternal();
  }

  bool executeTopUp(const std::string &id, double amount, int &outTrxId)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    User *target = nullptr;
    for (auto &u : users)
    {
      if (u.id == id)
      {
        target = &u;
        break;
      }
    }
    if (!target || amount <= 0)
      return false;

    target->balance += amount;
    saveUsersInternal();

    Transaction t;
    t.trxId = nextTrxId++;
    t.userId = id;
    t.type = "TOP UP";
    t.amount = amount;
    t.targetId = "-";
    t.timestamp = getCurrentTimestamp();
    t.status = "BERHASIL";

    transactions.push_back(t);
    saveTransactionsInternal();

    outTrxId = t.trxId;
    return true;
  }

  bool executeTransfer(const std::string &senderId, const std::string &recipientId, double amount, std::string typePrefix, int &outTrxId)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    User *sender = nullptr;
    User *recipient = nullptr;

    for (auto &u : users)
    {
      if (u.id == senderId)
        sender = &u;
      if (u.id == recipientId)
        recipient = &u;
    }

    if (!sender || !recipient || sender->balance < amount || amount <= 0)
    {
      return false;
    }

    sender->balance -= amount;
    recipient->balance += amount;

    saveUsersInternal();

    Transaction t1;
    t1.trxId = nextTrxId++;
    t1.userId = senderId;
    t1.type = typePrefix + " OUT";
    t1.amount = amount;
    t1.targetId = recipientId;
    t1.timestamp = getCurrentTimestamp();
    t1.status = "BERHASIL";

    Transaction t2;
    t2.trxId = nextTrxId++;
    t2.userId = recipientId;
    t2.type = typePrefix + " IN";
    t2.amount = amount;
    t2.targetId = senderId;
    t2.timestamp = t1.timestamp;
    t2.status = "BERHASIL";

    transactions.push_back(t1);
    transactions.push_back(t2);
    saveTransactionsInternal();

    outTrxId = t1.trxId;
    return true;
  }

  std::vector<Transaction> getUserTransactions(const std::string &uId)
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<Transaction> result;
    for (const auto &t : transactions)
    {
      if (t.userId == uId)
      {
        result.push_back(t);
      }
    }
    std::reverse(result.begin(), result.end());
    return result;
  }

  size_t getUserCount()
  {
    std::lock_guard<std::mutex> lock(dbMutex);
    return users.size();
  }
};

// ============================================================================
// 6. EMBEDDED WEB SERVER (Halaman Pembayaran Web HP)
//    Alur: GET /payment?merchant=ID  -> POST /payment/login
//          -> POST /payment/review   -> POST /payment/confirm (bukti)
//    Tambahan: GET /qr?merchant=ID (QR besar untuk layar laptop), GET /health
// ============================================================================
class EWalletWebServer
{
private:
  struct PaySession
  {
    std::string senderId;
    std::string merchantId;
    std::time_t expiresAt;
  };

  DatabaseManager &db;
  SOCKET serverSocket;
  std::atomic<bool> isRunning;
  std::atomic<bool> listening;
  std::thread serverThread;
  int port;

  std::mutex webMutex; // melindungi sessions, loginFails, publicHost, lastError
  std::map<std::string, PaySession> sessions;
  std::map<std::string, std::pair<int, std::time_t>> loginFails;
  std::string publicHost;
  std::string lastError;

  static constexpr int SESSION_TTL_SECONDS = 300;
  static constexpr int MAX_LOGIN_FAILS = 5;
  static constexpr int LOGIN_LOCK_SECONDS = 60;
  static constexpr int MIN_AMOUNT = 1000;

  // ---------------------------------------------------------------- HTML util
  static std::string css()
  {
    return std::string(
        "<style>"
        "* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }"
        "body { background-color: #f8fafc; color: #334155; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }"
        ".app-card { background: #ffffff; border-radius: 20px; border: 1px solid #e2e8f0; box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.04), 0 8px 10px -6px rgba(15, 23, 42, 0.02); width: 100%; max-width: 400px; padding: 28px; }"
        ".brand-header { text-align: center; margin-bottom: 24px; }"
        ".brand-logo { display: inline-flex; align-items: center; justify-content: center; width: 44px; height: 44px; background: #f1f5f9; color: #0f172a; border-radius: 12px; font-weight: 700; font-size: 18px; margin-bottom: 10px; }"
        ".brand-title { font-size: 18px; font-weight: 700; color: #0f172a; letter-spacing: -0.3px; }"
        ".brand-subtitle { font-size: 13px; color: #64748b; margin-top: 2px; }"
        ".recipient-box { background: #f8fafc; border: 1px solid #f1f5f9; border-radius: 14px; padding: 16px; margin-bottom: 22px; display: flex; align-items: center; gap: 12px; }"
        ".avatar-circle { width: 40px; height: 40px; border-radius: 50%; background: #e0e7ff; color: #4338ca; display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 15px; flex-shrink: 0; }"
        ".recipient-info label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; font-weight: 600; display: block; }"
        ".recipient-info .name { font-size: 15px; font-weight: 600; color: #1e293b; line-height: 1.2; margin-top: 2px; }"
        ".recipient-info .id { font-size: 12px; color: #64748b; }"
        ".form-group { margin-bottom: 16px; }"
        ".form-group label { display: block; font-size: 13px; font-weight: 500; color: #475569; margin-bottom: 6px; }"
        ".form-input { width: 100%; padding: 12px 14px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 10px; font-size: 14px; color: #0f172a; transition: all 0.2s ease; outline: none; }"
        ".form-input:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.12); }"
        ".btn-submit { width: 100%; background: #0f172a; color: #ffffff; border: none; padding: 13px; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s ease; margin-top: 8px; }"
        ".btn-submit:hover { background: #1e293b; }"
        ".badge-status { text-align: center; padding: 10px 14px; border-radius: 10px; font-size: 13px; font-weight: 600; margin-bottom: 20px; display: flex; align-items: center; justify-content: center; gap: 6px; }"
        ".badge-success { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }"
        ".badge-error { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }"
        ".receipt-detail { border-top: 1px dashed #e2e8f0; border-bottom: 1px dashed #e2e8f0; padding: 16px 0; margin: 18px 0; }"
        ".row-item { display: flex; justify-content: space-between; font-size: 13px; padding: 5px 0; color: #64748b; }"
        ".row-item .val { font-weight: 500; color: #1e293b; text-align: right; }"
        ".row-total { display: flex; justify-content: space-between; font-size: 15px; font-weight: 700; color: #0f172a; margin-top: 12px; padding-top: 10px; border-top: 1px solid #f1f5f9; }"
        ".btn-secondary { display: block; text-align: center; width: 100%; background: #f1f5f9; color: #475569; text-decoration: none; padding: 12px; border-radius: 10px; font-size: 13px; font-weight: 600; margin-top: 10px; transition: background 0.2s; border: none; cursor: pointer; }"
        ".btn-secondary:hover { background: #e2e8f0; }"
        ".qr-wrap { margin: 4px 0 14px; } .qr-wrap svg { width: 100%; height: auto; display: block; border: 1px solid #e2e8f0; border-radius: 12px; }"
        ".url-box { font-size: 11px; color: #475569; word-break: break-all; background: #f8fafc; border: 1px solid #f1f5f9; border-radius: 10px; padding: 10px; margin-bottom: 10px; }"
        ".muted { font-size: 12px; color: #64748b; text-align: center; }"
        "</style>");
  }

  static std::string pageHead(const std::string &title)
  {
    return "<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'>"
           "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
           "<title>" +
           title + "</title>" + css() +
           "</head><body><div class='app-card'>"
           "<div class='brand-header'><div class='brand-logo'>&#9889;</div>"
           "<div class='brand-title'>Elektro Wallet</div>"
           "<div class='brand-subtitle'>Pembayaran Instan via QR Code</div></div>";
  }

  static std::string pageFoot() { return "</div></body></html>"; }

  static std::string messageBox(bool ok, const std::string &title, const std::string &text)
  {
    std::string h = "<div class='badge-status " + std::string(ok ? "badge-success" : "badge-error") + "'>" + title + "</div>";
    if (!text.empty())
      h += "<p style='font-size: 13px; color: #64748b; text-align: center; margin-bottom: 20px;'>" + text + "</p>";
    return h;
  }

  static std::string recipientBox(const User &r)
  {
    std::string initial = "U";
    if (!r.name.empty() && std::isalnum(static_cast<unsigned char>(r.name[0])))
      initial = std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(r.name[0]))));
    return "<div class='recipient-box'><div class='avatar-circle'>" + initial + "</div>"
                                                                                "<div class='recipient-info'><label>Penerima Dana</label>"
                                                                                "<div class='name'>" +
           htmlEscape(r.name) + "</div>"
                                "<div class='id'>ID: " +
           htmlEscape(r.id) + "</div></div></div>";
  }

  static std::string backLink(const std::string &merchantId)
  {
    return "<a href='/payment?merchant=" + urlEncode(merchantId) + "' class='btn-secondary'>&larr; Kembali</a>";
  }

  static std::string expiredBox()
  {
    return messageBox(false, "Sesi Berakhir", "Sesi pembayaran sudah kedaluwarsa atau tidak valid. Pindai ulang QR Code untuk memulai lagi.");
  }

  static std::string formValue(const std::map<std::string, std::string> &form, const std::string &key)
  {
    auto it = form.find(key);
    return it == form.end() ? std::string() : it->second;
  }

  // Nominal Rupiah bulat saja (hanya digit) agar tidak ada format aneh seperti 1e9
  static bool parseAmount(const std::string &s, double &out)
  {
    if (s.empty() || s.size() > 12)
      return false;
    for (char c : s)
      if (!std::isdigit(static_cast<unsigned char>(c)))
        return false;
    out = stringToDouble(s);
    return out > 0;
  }

  // ------------------------------------------------------- sesi & anti brute-force
  static std::string generateToken()
  {
    std::random_device rd;
    uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ static_cast<uint64_t>(rd()) ^
                    static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::mt19937_64 gen(seed);
    std::stringstream ss;
    for (int i = 0; i < 2; i++)
      ss << std::hex << std::setfill('0') << std::setw(16) << gen();
    return ss.str();
  }

  std::string createSession(const std::string &senderId, const std::string &merchantId)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    std::time_t now = std::time(nullptr);
    for (auto it = sessions.begin(); it != sessions.end();)
    {
      if (it->second.expiresAt < now)
        it = sessions.erase(it);
      else
        ++it;
    }
    std::string token = generateToken();
    PaySession s;
    s.senderId = senderId;
    s.merchantId = merchantId;
    s.expiresAt = now + SESSION_TTL_SECONDS;
    sessions[token] = s;
    return token;
  }

  bool findSession(const std::string &token, PaySession &out, bool consume)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    auto it = sessions.find(token);
    if (it == sessions.end())
      return false;
    if (it->second.expiresAt < std::time(nullptr))
    {
      sessions.erase(it);
      return false;
    }
    out = it->second;
    if (consume)
      sessions.erase(it); // sekali pakai: mencegah pembayaran ganda saat halaman di-refresh
    return true;
  }

  int lockRemaining(const std::string &id)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    auto it = loginFails.find(id);
    if (it == loginFails.end())
      return 0;
    std::time_t now = std::time(nullptr);
    return (now < it->second.second) ? static_cast<int>(it->second.second - now) : 0;
  }

  void recordFailure(const std::string &id)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    if (loginFails.size() > 1000)
      loginFails.clear();
    auto &e = loginFails[id];
    e.first++;
    if (e.first >= MAX_LOGIN_FAILS)
    {
      e.first = 0;
      e.second = std::time(nullptr) + LOGIN_LOCK_SECONDS;
    }
  }

  void clearFailures(const std::string &id)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    loginFails.erase(id);
  }

  // ------------------------------------------------------------- halaman web
  std::string pageHome()
  {
    return pageHead("Elektro Wallet") +
           messageBox(true, "Server Aktif", "Pindai QR Code pembayaran dari aplikasi Elektro Wallet untuk memulai pembayaran.") +
           pageFoot();
  }

  // Langkah 1-3: tampilkan penerima (dari data QR) + form login pengirim
  std::string pagePayment(const std::string &merchantId)
  {
    User merchant = db.getUserCopy(merchantId);
    std::string h = pageHead("Pembayaran Elektro Wallet");
    if (merchant.id.empty() || merchant.status != "Aktif")
    {
      h += messageBox(false, "QR Code Tidak Dikenali", "Penerima tidak ditemukan atau akunnya tidak aktif.");
    }
    else
    {
      h += recipientBox(merchant);
      h += "<form action='/payment/login' method='POST'>";
      h += "<input type='hidden' name='merchant' value='" + htmlEscape(merchant.id) + "'>";
      h += "<div class='form-group'><label>User ID Anda</label><input type='text' name='sender_id' class='form-input' placeholder='Masukkan ID akun Anda' autocomplete='username' autocapitalize='off' required></div>";
      h += "<div class='form-group'><label>Password</label><input type='password' name='password' class='form-input' placeholder='Masukkan Password' autocomplete='current-password' required></div>";
      h += "<button type='submit' class='btn-submit'>Masuk &amp; Lanjutkan</button>";
      h += "</form>";
    }
    return h + pageFoot();
  }

  // Langkah 2-4: validasi akun pengirim, lalu minta nominal
  std::string pageLogin(const std::map<std::string, std::string> &form)
  {
    std::string merchantId = formValue(form, "merchant");
    std::string senderId = formValue(form, "sender_id");
    std::string password = formValue(form, "password");

    User merchant = db.getUserCopy(merchantId);
    std::string h = pageHead("Masuk Pembayaran");

    if (merchant.id.empty() || merchant.status != "Aktif")
      return h + messageBox(false, "Penerima Tidak Ditemukan", "Akun tujuan tidak terdaftar atau tidak aktif.") + pageFoot();

    int locked = lockRemaining(senderId);
    if (locked > 0)
      return h + messageBox(false, "Terlalu Banyak Percobaan", "Login web dikunci sementara. Coba lagi dalam " + std::to_string(locked) + " detik.") + backLink(merchantId) + pageFoot();

    User sender = db.getUserCopy(senderId);
    if (sender.id.empty() || sender.passwordHash != hashSecurity(password))
    {
      recordFailure(senderId);
      return h + messageBox(false, "Gagal Otentikasi", "User ID atau Password tidak sesuai.") + backLink(merchantId) + pageFoot();
    }
    clearFailures(senderId);

    if (sender.status != "Aktif")
      return h + messageBox(false, "Akun Tidak Aktif", "Akun Anda terblokir atau nonaktif.") + pageFoot();
    if (sender.id == merchant.id)
      return h + messageBox(false, "Tidak Dapat Dilanjutkan", "Anda tidak dapat membayar ke akun Anda sendiri.") + pageFoot();

    std::string token = createSession(sender.id, merchant.id);

    h += recipientBox(merchant);
    h += "<div class='receipt-detail'>";
    h += "<div class='row-item'><span>Akun Pengirim</span><span class='val'>" + htmlEscape(sender.name) + " (" + htmlEscape(sender.id) + ")</span></div>";
    h += "<div class='row-item'><span>Saldo Anda</span><span class='val'>" + formatRupiah(sender.balance) + "</span></div>";
    h += "</div>";
    h += "<form action='/payment/review' method='POST'>";
    h += "<input type='hidden' name='token' value='" + token + "'>";
    h += "<div class='form-group'><label>Nominal Pembayaran (Rp)</label><input type='number' name='amount' class='form-input' min='" + std::to_string(MIN_AMOUNT) + "' step='1' inputmode='numeric' placeholder='Contoh: 25000' required></div>";
    h += "<button type='submit' class='btn-submit'>Lanjutkan</button>";
    h += "</form>";
    return h + pageFoot();
  }

  // Langkah 5: ringkasan + tombol konfirmasi
  std::string pageReview(const std::map<std::string, std::string> &form)
  {
    std::string h = pageHead("Konfirmasi Pembayaran");
    PaySession s;
    std::string token = formValue(form, "token");
    if (!findSession(token, s, false))
      return h + expiredBox() + pageFoot();

    User sender = db.getUserCopy(s.senderId);
    User merchant = db.getUserCopy(s.merchantId);
    double amount = 0;

    if (!parseAmount(formValue(form, "amount"), amount) || amount < MIN_AMOUNT)
      return h + messageBox(false, "Nominal Tidak Valid", "Masukkan nominal bilangan bulat minimal " + formatRupiah(MIN_AMOUNT) + ".") +
             "<a href='javascript:history.back()' class='btn-secondary'>&larr; Ubah Nominal</a>" + pageFoot();
    if (sender.balance < amount)
      return h + messageBox(false, "Saldo Tidak Mencukupi", "Saldo Anda saat ini: <strong>" + formatRupiah(sender.balance) + "</strong>") +
             "<a href='javascript:history.back()' class='btn-secondary'>&larr; Ubah Nominal</a>" + pageFoot();

    h += "<div style='text-align: center; margin-bottom: 12px;'>";
    h += "<span style='font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;'>Total Pembayaran</span>";
    h += "<div style='font-size: 24px; font-weight: 700; color: #0f172a; margin-top: 2px;'>" + formatRupiah(amount) + "</div></div>";
    h += "<div class='receipt-detail'>";
    h += "<div class='row-item'><span>Penerima</span><span class='val'>" + htmlEscape(merchant.name) + " (" + htmlEscape(merchant.id) + ")</span></div>";
    h += "<div class='row-item'><span>Pengirim</span><span class='val'>" + htmlEscape(sender.name) + " (" + htmlEscape(sender.id) + ")</span></div>";
    h += "<div class='row-item'><span>Saldo Saat Ini</span><span class='val'>" + formatRupiah(sender.balance) + "</span></div>";
    h += "<div class='row-item'><span>Sisa Saldo</span><span class='val'>" + formatRupiah(sender.balance - amount) + "</span></div>";
    h += "</div>";
    h += "<form action='/payment/confirm' method='POST'>";
    h += "<input type='hidden' name='token' value='" + htmlEscape(token) + "'>";
    h += "<input type='hidden' name='amount' value='" + std::to_string(static_cast<long long>(amount)) + "'>";
    h += "<button type='submit' class='btn-submit'>Konfirmasi &amp; Bayar</button>";
    h += "</form>";
    h += backLink(merchant.id);
    return h + pageFoot();
  }

  // Langkah 6-8: validasi saldo, proses transaksi, simpan riwayat, tampilkan bukti
  std::string pageConfirm(const std::map<std::string, std::string> &form)
  {
    std::string h = pageHead("Bukti Pembayaran");
    PaySession s;
    if (!findSession(formValue(form, "token"), s, true))
      return h + expiredBox() + pageFoot();

    User sender = db.getUserCopy(s.senderId);
    User merchant = db.getUserCopy(s.merchantId);
    double amount = 0;

    if (sender.id.empty() || merchant.id.empty() || sender.status != "Aktif" || merchant.status != "Aktif" || sender.id == merchant.id)
      return h + messageBox(false, "Pembayaran Ditolak", "Akun pengirim atau penerima tidak valid.") + pageFoot();
    if (!parseAmount(formValue(form, "amount"), amount) || amount < MIN_AMOUNT)
      return h + messageBox(false, "Nominal Tidak Valid", "Silakan ulangi pembayaran dari awal.") + backLink(merchant.id) + pageFoot();

    int trxId = 0;
    if (!db.executeTransfer(sender.id, merchant.id, amount, "QR PAYMENT", trxId))
      return h + messageBox(false, "Pembayaran Gagal", "Saldo tidak mencukupi atau transaksi tidak dapat diproses. Saldo Anda tidak berubah.") + backLink(merchant.id) + pageFoot();

    h += messageBox(true, "&#10003; Pembayaran Berhasil", "");
    h += "<div style='text-align: center; margin-bottom: 12px;'>";
    h += "<span style='font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;'>Total Pembayaran</span>";
    h += "<div style='font-size: 24px; font-weight: 700; color: #0f172a; margin-top: 2px;'>" + formatRupiah(amount) + "</div></div>";
    h += "<div class='receipt-detail'>";
    h += "<div class='row-item'><span>No. Referensi</span><span class='val'>TRX" + std::to_string(trxId) + "</span></div>";
    h += "<div class='row-item'><span>Waktu Transaksi</span><span class='val'>" + getCurrentTimestamp() + "</span></div>";
    h += "<div class='row-item'><span>Pengirim</span><span class='val'>" + htmlEscape(sender.name) + " (" + htmlEscape(sender.id) + ")</span></div>";
    h += "<div class='row-item'><span>Penerima</span><span class='val'>" + htmlEscape(merchant.name) + " (" + htmlEscape(merchant.id) + ")</span></div>";
    h += "<div class='row-item'><span>Status</span><span class='val'>BERHASIL</span></div>";
    h += "</div>";
    h += "<button onclick='window.print()' class='btn-submit'>Simpan / Cetak Bukti</button>";
    return h + pageFoot();
  }

  // QR besar (SVG) untuk dibuka di browser laptop: lebih andal daripada QR di terminal
  std::string pageQr(const std::string &merchantId)
  {
    User m = db.getUserCopy(merchantId);
    std::string host;
    {
      std::lock_guard<std::mutex> lock(webMutex);
      host = publicHost;
    }
    std::string h = pageHead("QR Code Pembayaran");
    if (m.id.empty() || m.status != "Aktif")
      return h + messageBox(false, "Akun Tidak Ditemukan", "") + pageFoot();
    if (host.empty())
      return h + messageBox(false, "IP LAN Belum Terdeteksi", "Buka menu QR Code di aplikasi dan atur IP laptop terlebih dahulu.") + pageFoot();

    std::string payUrl = buildPaymentUrl(host, port, m.id);
    std::string svg = SimpleQRGenerator::toSvg(payUrl, 8);
    if (svg.empty())
      return h + messageBox(false, "URL Terlalu Panjang", "") + pageFoot();

    h += recipientBox(m);
    h += "<div class='qr-wrap'>" + svg + "</div>";
    h += "<p class='url-box'>" + htmlEscape(payUrl) + "</p>";
    h += "<p class='muted'>Pindai dengan kamera HP. HP dan laptop harus berada di jaringan Wi-Fi yang sama.</p>";
    return h + pageFoot();
  }

  // ---------------------------------------------------------------- HTTP
  static std::string buildHttpResponse(int code, const std::string &ctype, const std::string &body)
  {
    std::string status = "200 OK";
    if (code == 400)
      status = "400 Bad Request";
    else if (code == 404)
      status = "404 Not Found";
    else if (code == 405)
      status = "405 Method Not Allowed";
    std::string h = "HTTP/1.1 " + status + "\r\n";
    h += "Content-Type: " + ctype + "\r\n";
    h += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    h += "Cache-Control: no-store\r\n";
    h += "X-Content-Type-Options: nosniff\r\n";
    h += "Connection: close\r\n\r\n";
    return h + body;
  }

  static void sendAll(SOCKET s, const std::string &data)
  {
    size_t sent = 0;
    while (sent < data.size())
    {
      int n = send(s, data.c_str() + sent, static_cast<int>(data.size() - sent), 0);
      if (n <= 0)
        break;
      sent += static_cast<size_t>(n);
    }
  }

  // Membaca header lengkap lalu body sesuai Content-Length (body POST sering
  // datang di paket TCP terpisah, sehingga satu recv() saja tidak cukup).
  static bool readRequest(SOCKET s, std::string &method, std::string &url, std::string &body)
  {
    const size_t MAX_HEADER = 16384, MAX_BODY = 8192;
    std::string raw;
    char buf[2048];
    size_t headerEnd = std::string::npos;
    while (headerEnd == std::string::npos)
    {
      int n = recv(s, buf, sizeof(buf), 0);
      if (n <= 0)
        return false;
      raw.append(buf, static_cast<size_t>(n));
      headerEnd = raw.find("\r\n\r\n");
      if (headerEnd == std::string::npos && raw.size() > MAX_HEADER)
        return false;
    }

    std::stringstream line(raw.substr(0, raw.find("\r\n")));
    std::string protocol;
    line >> method >> url >> protocol;
    if (method.empty() || url.empty())
      return false;

    size_t contentLength = 0;
    std::string headersLower = toLowerStr(raw.substr(0, headerEnd));
    size_t p = headersLower.find("\r\ncontent-length:");
    if (p != std::string::npos)
      contentLength = static_cast<size_t>(std::strtoul(headersLower.c_str() + p + 17, nullptr, 10));
    if (contentLength > MAX_BODY)
      return false;

    size_t bodyStart = headerEnd + 4;
    while (raw.size() < bodyStart + contentLength)
    {
      int n = recv(s, buf, sizeof(buf), 0);
      if (n <= 0)
        return false;
      raw.append(buf, static_cast<size_t>(n));
    }
    body = raw.substr(bodyStart, contentLength);
    return true;
  }

  void clientHandler(SOCKET clientSocket)
  {
    setSocketTimeout(clientSocket, 5);
    std::string method, url, body;
    if (!readRequest(clientSocket, method, url, body))
    {
      closesocket(clientSocket);
      return;
    }

    size_t q = url.find('?');
    std::string path = (q == std::string::npos) ? url : url.substr(0, q);

    int code = 200;
    std::string ctype = "text/html; charset=utf-8";
    std::string out;
    const std::string notFound = pageHead("Tidak Ditemukan") + messageBox(false, "Halaman Tidak Ditemukan", "") + pageFoot();

    if (method == "GET")
    {
      if (path == "/payment" || path == "/pay")
      {
        std::string id = getQueryParam(url, "merchant");
        if (id.empty())
          id = getQueryParam(url, "recipient"); // kompatibel dengan format QR lama
        out = pagePayment(id);
      }
      else if (path == "/qr")
        out = pageQr(getQueryParam(url, "merchant"));
      else if (path == "/health")
      {
        ctype = "text/plain; charset=utf-8";
        out = "OK";
      }
      else if (path == "/")
        out = pageHome();
      else
      {
        code = 404;
        out = notFound;
      }
    }
    else if (method == "POST")
    {
      auto form = parseUrlFormData(body);
      if (path == "/payment/login")
        out = pageLogin(form);
      else if (path == "/payment/review")
        out = pageReview(form);
      else if (path == "/payment/confirm")
        out = pageConfirm(form);
      else
      {
        code = 404;
        out = notFound;
      }
    }
    else
    {
      code = 405;
      out = notFound;
    }

    sendAll(clientSocket, buildHttpResponse(code, ctype, out));
    closesocket(clientSocket);
  }

  void acceptLoop()
  {
    while (isRunning)
    {
      sockaddr_in clientAddr;
      socklen_t clientLen = sizeof(clientAddr);
      SOCKET clientSocket = accept(serverSocket, (sockaddr *)&clientAddr, &clientLen);
      if (!isRunning)
      {
        if (clientSocket != INVALID_SOCKET)
          closesocket(clientSocket);
        break;
      }
      if (clientSocket == INVALID_SOCKET)
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }
      std::thread(&EWalletWebServer::clientHandler, this, clientSocket).detach();
    }
  }

  void setError(const std::string &msg)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    lastError = msg;
  }

  // accept() yang sedang menunggu tidak selalu terbangun oleh close() di semua OS;
  // koneksi lokal singkat membangunkannya agar thread bisa berhenti dengan rapi.
  void wakeAccept()
  {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
      return;
    sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<unsigned short>(port));
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(s, (struct sockaddr *)&a, sizeof(a));
    closesocket(s);
  }

public:
  EWalletWebServer(DatabaseManager &database, int p = 8080)
      : db(database), serverSocket(INVALID_SOCKET), isRunning(false), listening(false), port(p) {}

  ~EWalletWebServer() { stop(); }

  // Bind/listen dilakukan SINKRON di sini, sehingga kegagalan (mis. port dipakai
  // program lain) langsung diketahui dan dapat ditampilkan, tidak diam-diam gagal.
  bool start()
  {
    if (isRunning)
      return listening;
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET)
    {
      setError("gagal membuat socket");
      return false;
    }
#ifndef _WIN32
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#endif
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0 -> dapat diakses dari perangkat lain di LAN
    addr.sin_port = htons(static_cast<unsigned short>(port));

    if (bind(serverSocket, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
      setError("bind() gagal di port " + std::to_string(port) + " (port sedang dipakai program lain?)");
      closesocket(serverSocket);
      serverSocket = INVALID_SOCKET;
      return false;
    }
    if (listen(serverSocket, 16) == SOCKET_ERROR)
    {
      setError("listen() gagal di port " + std::to_string(port));
      closesocket(serverSocket);
      serverSocket = INVALID_SOCKET;
      return false;
    }
    isRunning = true;
    listening = true;
    serverThread = std::thread(&EWalletWebServer::acceptLoop, this);
    return true;
  }

  void stop()
  {
    if (!isRunning.exchange(false))
      return;
    wakeAccept();
    if (serverThread.joinable())
      serverThread.join();
    if (serverSocket != INVALID_SOCKET)
    {
      closesocket(serverSocket);
      serverSocket = INVALID_SOCKET;
    }
    listening = false;
#ifdef _WIN32
    WSACleanup();
#endif
  }

  int getPort() const { return port; }
  bool isListening() const { return listening; }

  std::string getLastError()
  {
    std::lock_guard<std::mutex> lock(webMutex);
    return lastError;
  }

  void setPublicHost(const std::string &host)
  {
    std::lock_guard<std::mutex> lock(webMutex);
    publicHost = host;
  }
};

// ============================================================================
// 7. APLIKASI UTAMA ELEKTRO WALLET
// ============================================================================
class ElektroWalletApp
{
private:
  DatabaseManager db;
  EWalletWebServer webServer;
  std::string currentUserId;

  std::time_t loginLockoutUntil;
  std::time_t forgotPassLockoutUntil;
  std::time_t transferLockoutUntil;

  void printHeader(const std::string &title)
  {
    clearScreen();
    std::cout << "=======================================================\n";
    std::cout << "               ELEKTRO WALLET SYSTEM                   \n";
    std::cout << "=======================================================\n";
    std::cout << "  MENU: " << title << "\n";
    std::cout << "=======================================================\n";
  }

public:
  ElektroWalletApp()
      : db("users.txt", "transactions.txt"),
        webServer(db, getConfiguredPort()),
        currentUserId(""),
        loginLockoutUntil(0),
        forgotPassLockoutUntil(0),
        transferLockoutUntil(0)
  {
    const char *envIp = std::getenv("EWALLET_HOST_IP");
    if (envIp && isValidIPv4(envIp) && !isLoopbackOrUnusable(envIp))
      g_manualHostIP = envIp;
    webServer.start(); // hasilnya ditampilkan di menu utama & menu QR (isListening)
  }

  ~ElektroWalletApp()
  {
    webServer.stop();
  }

  // --- 1. REGISTRASI ---
  void handleRegistration()
  {
    printHeader("REGISTRASI AKUN BARU");
    std::string name, id, email, pass, pin, confirm;

    std::cout << "Masukkan Nama Lengkap : ";
    std::getline(std::cin >> std::ws, name);

    std::cout << "Masukkan User ID      : ";
    std::cin >> id;

    if (db.existsUser(id))
    {
      std::cout << "\n[ERROR] User ID sudah terdaftar! Gunakan ID lain.\n";
      pauseConsole();
      return;
    }

    std::cout << "Masukkan Email        : ";
    std::cin >> email;

    if (db.existsEmail(email))
    {
      std::cout << "\n[ERROR] Email sudah terdaftar pada sistem!\n";
      pauseConsole();
      return;
    }

    while (true)
    {
      pass = getMaskedInput("Masukkan Password     : ");
      if (isValidPassword(pass))
      {
        break;
      }
      else
      {
        std::cout << "\n[ERROR] Password tidak memenuhi kriteria keamanan!\n";
        std::cout << " - Minimal 8 karakter\n";
        std::cout << " - Harus memiliki Huruf Besar (A-Z)\n";
        std::cout << " - Harus memiliki Huruf Kecil (a-z)\n";
        std::cout << " - Harus memiliki Angka (0-9)\n";
        std::cout << "Silakan coba lagi.\n\n";
      }
    }

    while (true)
    {
      pin = getMaskedInput("Masukkan PIN (6 angka): ");
      if (isValidPin(pin))
      {
        break;
      }
      else
      {
        std::cout << "\n[ERROR] PIN tidak sesuai!\n";
        std::cout << " - Harus tepat 6 digit angka (0-9).\n";
        std::cout << "Silakan coba lagi.\n\n";
      }
    }

    std::cout << "\nKonfirmasi Pendaftaran? (Y/N): ";
    std::cin >> confirm;

    if (confirm == "Y" || confirm == "y")
    {
      User u;
      u.id = id;
      u.name = name;
      u.email = email;
      u.passwordHash = hashSecurity(pass);
      u.pinHash = hashSecurity(pin);
      u.balance = 0.0;
      u.status = "Aktif";
      u.createdAt = getCurrentTimestamp();

      if (db.addUser(u))
      {
        std::cout << "\n[BERHASIL] Akun Anda berhasil terdaftar! Silakan Login.\n";
      }
      else
      {
        std::cout << "\n[ERROR] Gagal menyimpan data ke database.\n";
      }
    }
    else
    {
      std::cout << "\n[BATAL] Pendaftaran dibatalkan.\n";
    }
    pauseConsole();
  }

  // --- 2. LOGIN ---
  bool handleLogin()
  {
    std::time_t now = std::time(nullptr);
    if (now < loginLockoutUntil)
    {
      int remaining = static_cast<int>(loginLockoutUntil - now);
      printHeader("LOGIN DIKUNCI SEMENTARA");
      std::cout << "\n[TERKUNCI] Login dikunci sementara karena 3 kali kesalahan!\n";
      std::cout << "Silakan tunggu " << remaining << " detik lagi sebelum mencoba.\n";
      pauseConsole();
      return false;
    }

    for (int attempt = 1; attempt <= 3; ++attempt)
    {
      printHeader("LOGIN AKUN");
      std::cout << "Percobaan Login " << attempt << " dari 3\n";
      std::cout << "-------------------------------------------------------\n";
      std::string id, pass;
      std::cout << "Masukkan User ID : ";
      std::cin >> id;
      pass = getMaskedInput("Masukkan Password: ");

      User u = db.getUserCopy(id);

      if (!u.id.empty() && u.passwordHash == hashSecurity(pass))
      {
        if (u.status != "Aktif")
        {
          std::cout << "\n[ERROR] Akun Anda terblokir / nonaktif!\n";
          pauseConsole();
          return false;
        }
        currentUserId = u.id;
        std::cout << "\n[BERHASIL] Login Sukses! Selamat datang, " << u.name << ".\n";
        pauseConsole();
        return true;
      }
      else
      {
        std::cout << "\n[ERROR] User ID atau Password yang Anda masukkan salah!\n";
        int sisa = 3 - attempt;
        if (sisa > 0)
        {
          std::cout << "Sisa percobaan login Anda: " << sisa << " kali.\n";
          pauseConsole();
        }
      }
    }

    loginLockoutUntil = std::time(nullptr) + 60;
    std::cout << "\n[TERKUNCI] Anda telah gagal login sebanyak 3 kali berturut-turut!\n";
    std::cout << "Fitur login dikunci sementara selama 1 menit (60 detik).\n";
    pauseConsole();
    return false;
  }

  // --- 3. LUPA PASSWORD ---
  void handleForgotPassword()
  {
    std::time_t now = std::time(nullptr);
    if (now < forgotPassLockoutUntil)
    {
      int remaining = static_cast<int>(forgotPassLockoutUntil - now);
      printHeader("LUPA PASSWORD TERKUNCI");
      std::cout << "\n[TERKUNCI] Fitur Lupa Password sedang dikunci sementara!\n";
      std::cout << "Silakan tunggu " << remaining << " detik lagi.\n";
      pauseConsole();
      return;
    }

    for (int attempt = 1; attempt <= 3; ++attempt)
    {
      printHeader("VERIFIKASI LUPA PASSWORD");
      std::cout << "Percobaan Verifikasi " << attempt << " dari 3\n";
      std::cout << "-------------------------------------------------------\n";
      std::string id, email;
      std::cout << "Masukkan User ID : ";
      std::cin >> id;
      std::cout << "Masukkan Email   : ";
      std::cin >> email;

      User u = db.getUserCopy(id);

      if (!u.id.empty() && u.email == email)
      {
        std::cout << "\n[VALIDASI SUKSES] Data cocok! Lanjutkan reset password.\n";
        std::string newPass;
        while (true)
        {
          newPass = getMaskedInput("Masukkan Password Baru: ");
          if (isValidPassword(newPass))
            break;
          std::cout << "\n[ERROR] Password baru tidak memenuhi kriteria (min 8 karakter, A-Z, a-z, 0-9)!\n";
        }
        std::string confirmPass = getMaskedInput("Konfirmasi Password   : ");

        if (newPass == confirmPass)
        {
          db.updatePassword(id, hashSecurity(newPass));
          std::cout << "\n[BERHASIL] Password berhasil diubah! Silakan login kembali.\n";
        }
        else
        {
          std::cout << "\n[ERROR] Konfirmasi password tidak cocok!\n";
        }
        pauseConsole();
        return;
      }
      else
      {
        std::cout << "\n[ERROR] Data User ID atau Email tidak terdaftar / tidak cocok!\n";
        int sisa = 3 - attempt;
        if (sisa > 0)
        {
          std::cout << "Sisa percobaan Anda: " << sisa << " kali.\n";
          pauseConsole();
        }
      }
    }

    forgotPassLockoutUntil = std::time(nullptr) + 60;
    std::cout << "\n[TERKUNCI] Anda telah 3 kali gagal melakukan verifikasi!\n";
    std::cout << "Fitur Lupa Password dikunci sementara selama 1 menit.\n";
    pauseConsole();
  }

  // --- 4. DASHBOARD FITUR ---
  void menuCekSaldo()
  {
    User curr = db.getUserCopy(currentUserId);
    printHeader("CEK SALDO");
    std::cout << " User ID  : " << curr.id << "\n";
    std::cout << " Nama     : " << curr.name << "\n";
    std::cout << "-------------------------------------------------------\n";
    std::cout << " SALDO ANDA SEKARANG: " << formatRupiah(curr.balance) << "\n";
    std::cout << "-------------------------------------------------------\n";
    pauseConsole();
  }

  void menuTopUp()
  {
    User curr = db.getUserCopy(currentUserId);
    printHeader("TOP UP SALDO");
    std::cout << " User ID  : " << curr.id << "\n";
    std::cout << " Nama     : " << curr.name << "\n";
    std::cout << "-------------------------------------------------------\n";
    std::cout << "Masukkan Nominal Top Up: Rp ";
    double amount;
    if (!(std::cin >> amount) || amount <= 0)
    {
      std::cin.clear();
      std::cin.ignore(1000, '\n');
      std::cout << "\n[ERROR] Nominal top up harus berupa angka dan lebih besar dari 0!\n";
      pauseConsole();
      return;
    }

    std::string pin = getMaskedInput("Masukkan PIN Anda untuk Konfirmasi Top Up: ");
    if (hashSecurity(pin) != curr.pinHash)
    {
      std::cout << "\n[ERROR] PIN Salah! Transaksi Top Up dibatalkan.\n";
      pauseConsole();
      return;
    }

    int trxId = 0;
    bool success = db.executeTopUp(currentUserId, amount, trxId);

    if (success)
    {
      User updated = db.getUserCopy(currentUserId);
      std::cout << "\n=======================================================\n";
      std::cout << "                BUKTI TOP UP BERHASIL                  \n";
      std::cout << "=======================================================\n";
      std::cout << " No. Transaksi : TRX" << trxId << "\n";
      std::cout << " Akun Tujuan   : " << updated.name << " (" << updated.id << ")\n";
      std::cout << " Nominal       : " << formatRupiah(amount) << "\n";
      std::cout << " Saldo Terbaru : " << formatRupiah(updated.balance) << "\n";
      std::cout << " Waktu         : " << getCurrentTimestamp() << "\n";
      std::cout << " Status        : BERHASIL\n";
      std::cout << "=======================================================\n";
    }
    else
    {
      std::cout << "\n[ERROR] Gagal memproses transaksi Top Up.\n";
    }
    pauseConsole();
  }

  void menuTransfer()
  {
    std::time_t now = std::time(nullptr);
    if (now < transferLockoutUntil)
    {
      int remaining = static_cast<int>(transferLockoutUntil - now);
      printHeader("TRANSFER DIKUNCI SEMENTARA");
      std::cout << "\n[TERKUNCI] Menu Transfer sedang dikunci sementara!\n";
      std::cout << "Silakan tunggu " << remaining << " detik lagi.\n";
      pauseConsole();
      return;
    }

    User recipient;
    std::string targetId;

    for (int attempt = 1; attempt <= 3; ++attempt)
    {
      printHeader("TRANSFER SALDO");
      std::cout << "Percobaan User ID Penerima " << attempt << " dari 3\n";
      std::cout << "-------------------------------------------------------\n";
      std::cout << "Masukkan User ID Penerima: ";
      std::cin >> targetId;

      if (targetId == currentUserId)
      {
        std::cout << "\n[ERROR] Anda tidak dapat melakukan transfer ke akun sendiri!\n";
      }
      else
      {
        recipient = db.getUserCopy(targetId);
        if (!recipient.id.empty())
          break;
        std::cout << "\n[ERROR] User ID Penerima tidak terdaftar di database!\n";
      }

      int sisa = 3 - attempt;
      if (sisa > 0)
      {
        std::cout << "Sisa percobaan Anda: " << sisa << " kali.\n";
        pauseConsole();
      }
    }

    if (recipient.id.empty())
    {
      transferLockoutUntil = std::time(nullptr) + 60;
      std::cout << "\n[TERKUNCI] Anda telah 3 kali gagal memasukkan User ID Penerima!\n";
      std::cout << "Menu Transfer dikunci sementara selama 1 menit.\n";
      pauseConsole();
      return;
    }

    User sender = db.getUserCopy(currentUserId);

    std::cout << "\nPenerima Terdeteksi  : " << recipient.name << " (" << recipient.id << ")\n";
    std::cout << "Masukkan Nominal Transfer: Rp ";
    double amount;
    if (!(std::cin >> amount) || amount <= 0)
    {
      std::cin.clear();
      std::cin.ignore(1000, '\n');
      std::cout << "\n[ERROR] Nominal transfer harus angka dan lebih dari 0!\n";
      pauseConsole();
      return;
    }

    if (amount > sender.balance)
    {
      std::cout << "\n[ERROR] Saldo Anda tidak mencukupi untuk transfer ini!\n";
      pauseConsole();
      return;
    }

    bool pinValid = false;
    for (int pinAttempt = 1; pinAttempt <= 3; ++pinAttempt)
    {
      std::string pin = getMaskedInput("Masukkan PIN Anda untuk Konfirmasi: ");
      if (hashSecurity(pin) == sender.pinHash)
      {
        pinValid = true;
        break;
      }
      else
      {
        std::cout << "\n[ERROR] PIN Salah! (Percobaan " << pinAttempt << " dari 3)\n";
      }
    }

    if (!pinValid)
    {
      std::cout << "\n[BATAL] Transaksi Transfer dibatalkan karena kesalahan PIN.\n";
      pauseConsole();
      return;
    }

    int trxId = 0;
    bool success = db.executeTransfer(currentUserId, recipient.id, amount, "TRANSFER", trxId);

    if (success)
    {
      std::cout << "\n=======================================================\n";
      std::cout << "                BUKTI TRANSFER BERHASIL                \n";
      std::cout << "=======================================================\n";
      std::cout << " No. Transaksi : TRX" << trxId << "\n";
      std::cout << " Pengirim      : " << sender.name << " (" << sender.id << ")\n";
      std::cout << " Penerima      : " << recipient.name << " (" << recipient.id << ")\n";
      std::cout << " Nominal       : " << formatRupiah(amount) << "\n";
      std::cout << " Waktu         : " << getCurrentTimestamp() << "\n";
      std::cout << " Status        : BERHASIL\n";
      std::cout << "=======================================================\n";
    }
    else
    {
      std::cout << "\n[ERROR] Gagal memproses transaksi transfer.\n";
    }
    pauseConsole();
  }

  void openInBrowser(const std::string &url)
  {
    // url hanya berisi karakter aman (host + ID yang sudah di-percent-encode)
#ifdef _WIN32
    std::string cmd = "start \"\" \"" + url + "\"";
#elif defined(__APPLE__)
    std::string cmd = "open '" + url + "' >/dev/null 2>&1 &";
#else
    std::string cmd = "xdg-open '" + url + "' >/dev/null 2>&1 &";
#endif
    if (system(cmd.c_str()) != 0)
      std::cout << "\n[INFO] Tidak dapat membuka browser otomatis. Buka manual: " << url << "\n";
  }

  void menuQRCode()
  {
    // Buang sisa newline dari pilihan menu (cin >> choice); setelah ini hanya getline.
    std::cin.ignore(10000, '\n');
    std::string notice = "";

    while (true)
    {
      User curr = db.getUserCopy(currentUserId);
      printHeader("QR CODE PEMBAYARAN VIA HP");
      std::cout << " Akun Penerima     : " << curr.name << " (" << curr.id << ")\n\n";

      int port = webServer.getPort();
      if (!webServer.isListening())
      {
        std::cout << " [ERROR] Web server TIDAK berjalan: " << webServer.getLastError() << "\n";
        std::cout << " QR Code tidak ditampilkan karena halaman pembayarannya tidak bisa diakses.\n";
        std::cout << " Tutup program yang memakai port " << port << ", atau ganti port lewat variabel\n";
        std::cout << " environment EWALLET_PORT, lalu jalankan ulang program.\n";
        std::cout << "\nTekan [ENTER] untuk kembali...";
        std::string dummy;
        std::getline(std::cin, dummy);
        return;
      }

      std::string localIP = getLocalIPAddress();
      if (localIP.empty())
      {
        std::cout << " [PERINGATAN] IP LAN laptop tidak terdeteksi (laptop belum terhubung ke Wi-Fi/hotspot?).\n";
        std::cout << " Alamat 127.0.0.1/localhost TIDAK dapat dipakai di QR Code.\n";
        std::cout << " Masukkan IP laptop secara manual (contoh 192.168.1.10), kosongkan untuk kembali: ";
        std::string manual;
        std::getline(std::cin, manual);
        if (manual.empty())
          return;
        if (!isValidIPv4(manual) || isLoopbackOrUnusable(manual))
        {
          std::cout << "\n[ERROR] IP tidak valid atau berupa alamat loopback. Tekan [ENTER]...";
          std::getline(std::cin, manual);
          continue;
        }
        g_manualHostIP = manual;
        continue;
      }

      webServer.setPublicHost(localIP);
      std::string payUrl = buildPaymentUrl(localIP, port, curr.id);
      std::string viewUrl = "http://localhost:" + std::to_string(port) + "/qr?merchant=" + urlEncode(curr.id);
      std::vector<std::string> cands = getLocalIPCandidates();

      std::cout << " IP Laptop (LAN)   : " << localIP << (g_manualHostIP.empty() ? "  [otomatis]" : "  [manual]") << "\n";
      std::cout << " Web Server        : BERJALAN di port " << port << "\n";
      if (cands.size() > 1)
      {
        std::cout << " IP lain terdeteksi: ";
        for (const auto &c : cands)
          if (c != localIP)
            std::cout << c << "  ";
        std::cout << "(tekan I jika IP di atas bukan yang dipakai HP)\n";
      }
      std::cout << " URL di dalam QR   : " << payUrl << "\n";
      std::cout << "\n Pindai QR di bawah dengan kamera HP (HP & laptop harus satu Wi-Fi/hotspot):\n";

      SimpleQRGenerator::printToConsole(payUrl);

      std::cout << " Jika QR di terminal sulit dipindai (warna/ukuran huruf terminal), buka versi\n";
      std::cout << " browser yang tajam di laptop: " << viewUrl << "\n";
      std::cout << " Jika HP tidak bisa membuka link: cek firewall laptop (izinkan port " << port << ").\n";
      if (!notice.empty())
        std::cout << "\n >> " << notice << "\n";
      notice = "";

      std::cout << "\n [ENTER] Kembali  [B] Buka QR di browser  [I] Ganti IP  [T] Tes server\n";
      std::cout << " Pilihan: ";
      std::string opt;
      std::getline(std::cin, opt);

      if (opt.empty())
        return;
      char ch = static_cast<char>(std::toupper(static_cast<unsigned char>(opt[0])));
      if (ch == 'B')
      {
        openInBrowser(viewUrl);
        notice = "Membuka " + viewUrl;
      }
      else if (ch == 'I')
      {
        std::cout << " IP baru (kosongkan = deteksi otomatis): ";
        std::string manual;
        std::getline(std::cin, manual);
        if (manual.empty())
        {
          g_manualHostIP.clear();
          notice = "Kembali ke deteksi IP otomatis.";
        }
        else if (!isValidIPv4(manual) || isLoopbackOrUnusable(manual))
          notice = "IP tidak valid / loopback, tidak diubah.";
        else
        {
          g_manualHostIP = manual;
          notice = "IP diubah ke " + manual;
        }
      }
      else if (ch == 'T')
      {
        std::string detail;
        bool ok = selfTestHttp(localIP, port, detail);
        notice = std::string(ok ? "[OK] " : "[GAGAL] ") + detail +
                 ". (Tes ini dari laptop sendiri; keberhasilan dari HP tetap harus dicek.)";
      }
    }
  }

  void menuAktivitas()
  {
    User curr = db.getUserCopy(currentUserId);
    printHeader("RIWAYAT TRANSAKSI");
    std::vector<Transaction> history = db.getUserTransactions(currentUserId);

    if (history.empty())
    {
      std::cout << "Belum ada riwayat aktivitas transaksi.\n";
      pauseConsole();
      return;
    }

    std::stringstream ss;
    ss << "================================================================================\n";
    ss << std::left << std::setw(8) << "ID TRX"
       << std::setw(16) << "TIPE"
       << std::setw(16) << "NOMINAL"
       << std::setw(12) << "TUJUAN"
       << std::setw(20) << "WAKTU"
       << std::setw(10) << "STATUS" << "\n";
    ss << "================================================================================\n";

    for (const auto &t : history)
    {
      ss << std::left << std::setw(8) << t.trxId
         << std::setw(16) << t.type
         << std::setw(16) << formatRupiah(t.amount)
         << std::setw(12) << t.targetId
         << std::setw(20) << t.timestamp
         << std::setw(10) << t.status << "\n";
    }
    ss << "================================================================================\n";

    std::cout << ss.str();

    std::cout << "\nApakah Anda ingin mencetak struk aktivitas ini ke file teks? (Y/N): ";
    std::string opt;
    std::cin >> opt;

    if (opt == "Y" || opt == "y")
    {
      std::string fileName = "bukti_aktivitas_" + curr.id + ".txt";
      std::ofstream outFile(fileName);
      outFile << "BUKTI RIWAYAT TRANSAKSI ELEKTRO WALLET\n";
      outFile << "Nama User : " << curr.name << " (ID: " << curr.id << ")\n";
      outFile << "Dicetak   : " << getCurrentTimestamp() << "\n\n";
      outFile << ss.str();
      outFile.close();

      std::cout << "\n[BERHASIL] File bukti aktivitas tersimpan di: " << fileName << "\n";
    }
    pauseConsole();
  }

  void menuProfil()
  {
    User curr = db.getUserCopy(currentUserId);
    printHeader("PROFIL PENGGUNA");
    std::cout << " Nama Lengkap : " << curr.name << "\n";
    std::cout << " User ID      : " << curr.id << "\n";
    std::cout << " Email        : " << curr.email << "\n";
    std::cout << " Status Akun  : " << curr.status << "\n";
    std::cout << " Tgl Dibuat   : " << curr.createdAt << "\n";
    pauseConsole();
  }

  void menuUbahPin()
  {
    User curr = db.getUserCopy(currentUserId);
    printHeader("UBAH / LUPA PIN");
    std::string pass = getMaskedInput("Masukkan Password Anda untuk Otentikasi: ");

    if (hashSecurity(pass) == curr.passwordHash)
    {
      std::string newPin;
      while (true)
      {
        newPin = getMaskedInput("Masukkan PIN Baru (6 angka): ");
        if (isValidPin(newPin))
          break;
        std::cout << "\n[ERROR] PIN harus tepat 6 digit angka!\n\n";
      }
      std::string confirmPin = getMaskedInput("Konfirmasi PIN Baru       : ");

      if (newPin == confirmPin)
      {
        db.updatePin(currentUserId, hashSecurity(newPin));
        std::cout << "\n[BERHASIL] PIN Baru Anda berhasil diperbarui!\n";
      }
      else
      {
        std::cout << "\n[ERROR] Konfirmasi PIN tidak cocok!\n";
      }
    }
    else
    {
      std::cout << "\n[ERROR] Password Salah! Perubahan PIN ditolak.\n";
    }
    pauseConsole();
  }

  void showDashboard()
  {
    while (true)
    {
      User curr = db.getUserCopy(currentUserId);

      printHeader("DASHBOARD PENGGUNA");
      std::cout << " Selamat Datang, " << curr.name << " [ID: " << curr.id << "]\n";
      std::cout << "-------------------------------------------------------\n";
      std::cout << " 1. Cek Saldo\n";
      std::cout << " 2. Top Up Saldo\n";
      std::cout << " 3. Transfer Saldo\n";
      std::cout << " 4. QR Code Pembayaran (Web / HP)\n";
      std::cout << " 5. Riwayat Transaksi / Aktivitas\n";
      std::cout << " 6. Profil Pengguna\n";
      std::cout << " 7. Ubah PIN / Lupa PIN\n";
      std::cout << " 8. Logout\n";
      std::cout << "-------------------------------------------------------\n";
      std::cout << " Pilih Menu (1-8): ";

      int choice;
      if (!(std::cin >> choice))
      {
        std::cin.clear();
        std::cin.ignore(1000, '\n');
        continue;
      }

      switch (choice)
      {
      case 1:
        menuCekSaldo();
        break;
      case 2:
        menuTopUp();
        break;
      case 3:
        menuTransfer();
        break;
      case 4:
        menuQRCode();
        break;
      case 5:
        menuAktivitas();
        break;
      case 6:
        menuProfil();
        break;
      case 7:
        menuUbahPin();
        break;
      case 8:
        std::cout << "\n[LOGOUT] Anda telah keluar dari akun.\n";
        currentUserId = "";
        pauseConsole();
        return;
      default:
        std::cout << "\n[ERROR] Pilihan menu tidak valid!\n";
        pauseConsole();
      }
    }
  }

  void run()
  {
    while (true)
    {
      printHeader("UTAMA - ELEKTRO WALLET");
      std::cout << " Total Terdaftar : " << db.getUserCount() << " Pengguna\n";
      std::string shownIP = getLocalIPAddress();
      std::cout << " IP Laptop Saat Ini: " << (shownIP.empty() ? "(tidak terdeteksi - atur di menu QR)" : shownIP) << "\n";
      if (webServer.isListening())
        std::cout << " Web Server Status: BERJALAN di Port " << webServer.getPort() << "\n";
      else
        std::cout << " Web Server Status: GAGAL - " << webServer.getLastError() << "\n";
      std::cout << "-------------------------------------------------------\n";
      std::cout << " 1. Login Akun\n";
      std::cout << " 2. Registrasi Akun Baru\n";
      std::cout << " 3. Lupa Password\n";
      std::cout << " 4. Keluar Program\n";
      std::cout << "-------------------------------------------------------\n";
      std::cout << " Pilih Menu (1-4): ";

      int mainChoice;
      if (!(std::cin >> mainChoice))
      {
        std::cin.clear();
        std::cin.ignore(1000, '\n');
        continue;
      }

      if (mainChoice == 1)
      {
        if (handleLogin())
        {
          showDashboard();
        }
      }
      else if (mainChoice == 2)
      {
        handleRegistration();
      }
      else if (mainChoice == 3)
      {
        handleForgotPassword();
      }
      else if (mainChoice == 4)
      {
        printHeader("TERIMA KASIH");
        std::cout << " Terima kasih telah menggunakan sistem Elektro Wallet.\n";
        break;
      }
      else
      {
        std::cout << "\n[ERROR] Pilihan menu tidak valid!\n";
        pauseConsole();
      }
    }
  }
};

// ============================================================================
// 8. MAIN FUNCTION
// ============================================================================
int main()
{
  ElektroWalletApp app;
  app.run();
  return 0;
}