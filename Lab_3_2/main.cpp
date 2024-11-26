#include "modCipherBeta.h"

#include <UnitTest++/UnitTest++.h>

std::string converter(const std::wstring &wstr) {
  std::wstring_convert<std::codecvt_utf8<wchar_t>> codec;
  return codec.to_bytes(wstr);
}

struct KeyB_fixture {
  Cipher *p;
  KeyB_fixture() { p = new Cipher(L"4"); }
  ~KeyB_fixture() { delete p; }
};

 SUITE(KeyTest) {
   TEST(ValidKey) {
     CHECK_EQUAL("ЕОБВРОАК", converter((Cipher(L"4").encrypt(L"АРБЕКОВО"))));
   }
   TEST(NegativeKey) { CHECK_THROW(Cipher cp(L"-4"), cipher_error); }
   TEST(SpaceInKey) { CHECK_THROW(Cipher cp(L"1 0"), cipher_error); }
   TEST(EmptyKey) { CHECK_THROW(Cipher cp(L""), cipher_error); }
   TEST(NotNumKey) { CHECK_THROW(Cipher cp(L"Б1,"), cipher_error); }
   TEST(TheKeyExceedsHalfTheText) {
     Cipher cp(L"8");
     CHECK_THROW(cp.encrypt(L"АРБЕКОВО"), cipher_error);
   }
 }

SUITE(EncryptTest) {
  TEST_FIXTURE(KeyB_fixture, UpCaseString) {
    CHECK_EQUAL("ЕОБВРОАК", converter(p->encrypt(L"АРБЕКОВО")));
  }
  TEST_FIXTURE(KeyB_fixture, LowCaseString) {
    CHECK_EQUAL("ЕОБВРОАК", converter(p->encrypt(L"арбеково")));
  }
  TEST_FIXTURE(KeyB_fixture, PunctString) {
    CHECK_EQUAL("ЕОБВРОАК", converter(p->encrypt(L"АРБЕКОВО!")));
  }
  TEST_FIXTURE(KeyB_fixture, NumberString) {
    CHECK_EQUAL("ЕОБВРОАК", converter(p->encrypt(L"АРБЕКОВО228")));
  }
  TEST_FIXTURE(KeyB_fixture, EmptyString) {
    CHECK_THROW(p->encrypt(L""), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, WithoutAlphaString) {
    CHECK_THROW(p->encrypt(L"133799950"), cipher_error);
  }
}
SUITE(DecryptText) {
  TEST_FIXTURE(KeyB_fixture, UpCaseString) {
    CHECK_EQUAL("АРБЕКОВО", converter(p->decrypt(L"ЕОБВРОАК")));
  }
  TEST_FIXTURE(KeyB_fixture, LowCaseString) {
    CHECK_THROW(p->decrypt(L"ЕОБВроак"), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, SpaceString) {
    CHECK_THROW(p->decrypt(L"ЕОБВ РОАК"), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, NumberString) {
    CHECK_THROW(p->decrypt(L"ЕОБВ2РОАК"), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, PunctString) {
    CHECK_THROW(p->decrypt(L"ЕОБВРОАК!"), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, EmptyString) {
    CHECK_THROW(p->decrypt(L""), cipher_error);
  }
}

int main(int argc, char **argv) {
  locale loc("ru_RU.UTF-8");
  locale::global(loc);
  return UnitTest::RunAllTests();
}