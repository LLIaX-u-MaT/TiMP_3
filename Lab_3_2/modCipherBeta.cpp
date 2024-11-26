#include "modCipherBeta.h"

Cipher::Cipher(const std::wstring &key_str) : key(getValidKey(key_str)) {}
wstring Cipher::encrypt(const wstring &text) {
  wstring tmp = getValidOpenText(text);
  if(key > static_cast<int>(text.length()) / 2) {
  throw cipher_error("Длина ключа не должна превышать половину длины текста");
  }
  int index = 0;
  int len = tmp.length();
  int rows = ceil(static_cast<double>(len) / key);
  wchar_t tabl[rows][key];

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < key; j++) {
      if (index < len) {
        tabl[i][j] = tmp[index++];
      } else {
        tabl[i][j] = L' ';
      }
    }
  }

  wstring cipherText;
  for (int i = key - 1; i >= 0; i--) {
    for (int j = 0; j < rows; j++) {
      if (tabl[j][i] == L' ') {
        cipherText += L'*';
      } else {
        cipherText += tabl[j][i];
      }
    }
  }
  return cipherText;
}

wstring Cipher::decrypt(const wstring &cipherText) {
  wstring tmp = getValidCipherText(cipherText);
  int len = tmp.length();
  int rows = ceil(static_cast<double>(len) / key);
  wchar_t tabl[rows][key];

  int index = 0;
  for (int i = key - 1; i >= 0; i--) {
    for (int j = 0; j < rows; ++j) {
      if (index < len) {
        tabl[j][i] = tmp[index++];
      } else {
        tabl[j][i] = L' ';
      }
    }
  }

  wstring decryptedText;
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < key; j++) {
      if (tabl[i][j] == L'*') {
        decryptedText += L' ';
      } else {
        decryptedText += tabl[i][j];
      }
    }
  }
  return decryptedText;
}
inline std::wstring Cipher::getValidOpenText(const std::wstring &s) {
  std::wstring tmp;
  for (auto c : s) {
    if (iswalpha(c)) {
      if (iswlower(c))
        tmp.push_back(towupper(c));
      else
        tmp.push_back(c);
    } else if (iswspace(c)) {
      tmp.push_back(c);
    }
  }
  if (tmp.empty())
    throw cipher_error("Пустой открытый текст");
  return tmp;
}
inline std::wstring Cipher::getValidCipherText(const std::wstring &s) {
  if (s.empty())
    throw cipher_error("Пустой зашифрованный текст");

  std::wstring tmp(s);
  std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
  std::string m = converter.to_bytes(tmp);

  for (auto c : s) {
    if (c == L'*') {
      continue;
    }
    if (!iswupper(c)) {
      throw cipher_error(std::string("Неправильный зашифрованный текст: ") + m);
    }
  }
  return tmp;
}
inline int Cipher::getValidKey(const std::wstring &key_str) {
  if (key_str.empty())
    throw cipher_error("Пустой ключ");

  for (auto &c : key_str) {
    if (!iswdigit(c)) {
      throw cipher_error("Некорректный ключ: " +
                         std::string(key_str.begin(), key_str.end()));
    }
  }
  int key = std::stoi(std::string(key_str.begin(), key_str.end()));
  if (key <= 1) {
    throw cipher_error("Некорректный ключ");
  }
  return key;
}
