#include "modAlphaCipher.h"

#include <UnitTest++/UnitTest++.h>
#include <codecvt>
#include <locale>
using namespace std;

std::string converter(const std::wstring &wstr) {
  std::wstring_convert<std::codecvt_utf8<wchar_t>> codec;
  return codec.to_bytes(wstr);
}

struct KeyB_fixture {
  modAlphaCipher *p;
  KeyB_fixture() { p = new modAlphaCipher(L"Б"); }
  ~KeyB_fixture() { delete p; }
};
SUITE(KeyTest) {
  TEST(ValidKey) {
    CHECK_EQUAL("ЛЯСРЩЯНЭ",
                converter(modAlphaCipher(L"ЛОР").encrypt(L"АРБЕКОВО")));
  }
  TEST(LongKey) {
    CHECK_EQUAL(
        "ЛЯСРЩЯНЭ",
        converter(modAlphaCipher(L"ЛОРЛОРЛОРЛОР").encrypt(L"АРБЕКОВО")));
  }
  TEST(LowCaseKey) {
    CHECK_EQUAL("ЛЯСРЩЯНЭ",
                converter(modAlphaCipher(L"лор").encrypt(L"АРБЕКОВО")));
  }
  TEST(DigitsInKey) { CHECK_THROW(modAlphaCipher cp(L"Б1"), cipher_error); }
  TEST(PunctuationInKey) {
    CHECK_THROW(modAlphaCipher cp(L"Б,В"), cipher_error);
  }
  TEST(WhitespaceInKey) {
    CHECK_THROW(modAlphaCipher cp(L"Б В"), cipher_error);
  }
  TEST(EmptyKey) { CHECK_THROW(modAlphaCipher cp(L""), cipher_error); }
  TEST(WeakKey) { CHECK_THROW(modAlphaCipher cp(L"AAA"), cipher_error); }
}

SUITE(EncryptTest) {
  TEST_FIXTURE(KeyB_fixture, UpCaseString) {
    CHECK_EQUAL(
        "ВЬТУСПОПДБАМЙТЙЧБРСЬДБЁУОБМЁОЙГПДПРТБ",
        converter(p->encrypt(L"БЫСТРОНОГАЯЛИСИЦАПРЫГАЕТНАЛЕНИВОГОПСА")));
  }
  TEST_FIXTURE(KeyB_fixture, LowCaseString) {
    CHECK_EQUAL(
        "ВЬТУСПОПДБАМЙТЙЧБРСЬДБЁУОБМЁОЙГПДПРТБ",
        converter(p->encrypt(L"быстроногаялисицапрыгаетналенивогопса")));
  }
  TEST_FIXTURE(KeyB_fixture, StringWithWhitespaceAndPunct) {
    CHECK_EQUAL("ВЬТУСПОПДБАМЙТЙЧБРСЬДБЁУОБМЁОЙГПДПРТБ",
                converter(p->encrypt(
                    L"БЫСТРОНОГАЯ ЛИСИЦА ПРЫГАЕТ НА ЛЕНИВОГО ПСА!!!")));
  }
  TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
    CHECK_EQUAL("ТОПГЬНДПЕПН", converter(p->encrypt(L"С Новым 2019 Годом")));
  }
  TEST_FIXTURE(KeyB_fixture, EmptyString) {
    CHECK_THROW(p->encrypt(L""), cipher_error);
  }

  TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
    CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
  }
  TEST(MaxShiftKey) {
    CHECK_EQUAL("АЪРСПНМНВЯЮКЗРЗХЯОПЪВЯДСМЯКДМЗБНВНОРЯ",
                converter(modAlphaCipher(L"Я").encrypt(
                    L"БЫСТРОНОГАЯЛИСИЦАПРЫГАЕТНАЛЕНИВОГОПСА")));
  }
}
SUITE(DecryptText) {
  TEST_FIXTURE(KeyB_fixture, UpCaseString) {
    CHECK_EQUAL(
        "БЫСТРОНОГАЯЛИСИЦАПРЫГАЕТНАЛЕНИВОГОПСА",
        converter(p->decrypt(L"ВЬТУСПОПДБАМЙТЙЧБРСЬДБЁУОБМЁОЙГПДПРТБ")));
  }
  TEST_FIXTURE(KeyB_fixture, LowCaseString) {
    CHECK_THROW(p->decrypt(L"вьтУСПОПДБАМЙТЙЧБРСЬДБЁУОБМЁОЙГПДПРТБ"),
                cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
    CHECK_THROW(p->decrypt(L"ВЬТУ СПОП ДБА МЙТЙЧ БРСЬ ДБЁ УОБМ ЁОЙ ГПДП РТБ"),
                cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, DigitsInString) {
    CHECK_THROW(p->decrypt(L"ТОПГЬН2019ДПЕПН"), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, PunctuationInString) {
    CHECK_THROW(p->decrypt(L"ТОПГЬН,ДПЕПН"), cipher_error);
  }
  TEST_FIXTURE(KeyB_fixture, EmptyString) {
    CHECK_THROW(p->decrypt(L""), cipher_error);
  }
  TEST(MaxShiftKey) {
    CHECK_EQUAL("БЫСТРОНОГАЯЛИСИЦАПРЫГАЕТНАЛЕНИВОГОПСА",
                converter(modAlphaCipher(L"Я").decrypt(
                    L"АЪРСПНМНВЯЮКЗРЗХЯОПЪВЯДСМЯКДМЗБНВНОРЯ")));
  }
}
int main(int argc, char **argv) {
  locale loc("ru_RU.UTF-8");
  locale::global(loc);
  return UnitTest::RunAllTests();
}
