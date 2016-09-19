/*
* TLS CBC+HMAC AEAD
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CBC_HMAC_AEAD_H__
#define BOTAN_TLS_CBC_HMAC_AEAD_H__

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>

namespace Botan {

/**
* TLS CBC+HMAC AEAD base class (GenericBlockCipher in TLS spec)
* This is the weird TLS-specific mode, not for general consumption.
*/
class TLS_CBC_HMAC_AEAD_Mode : public AEAD_Mode
   {
   public:
      void set_associated_data(const byte ad[], size_t ad_len) override;

      std::string name() const override;

      size_t update_granularity() const override;

      Key_Length_Specification key_spec() const override;

      bool valid_nonce_length(size_t nl) const override;

      size_t tag_size() const override { return m_tag_size; }

      void clear() override;

      std::string provider() const override;
   protected:
      TLS_CBC_HMAC_AEAD_Mode(const std::string& cipher_name,
                             size_t cipher_keylen,
                             const std::string& mac_name,
                             size_t mac_keylen,
                             bool use_explicit_iv,
                             bool use_encrypt_then_mac);

   private:
      void update(secure_vector<byte>& blocks, size_t offset = 0) override;

      secure_vector<byte> start_raw(const byte nonce[], size_t nonce_len) override;

      void key_schedule(const byte key[], size_t length) override;

      std::unique_ptr<BlockCipher> m_block_cipher;
      std::unique_ptr<MessageAuthenticationCode> m_mac;

      size_t m_cipher_keylen;
      size_t m_mac_keylen;
      size_t m_iv_size;
      size_t m_tag_size;
      bool m_uses_encrypt_then_mac;

      secure_vector<byte> m_cbc_state;
      std::vector<byte> m_ad, m_msg;
   };

/**
* TLS_CBC_HMAC_AEAD Encryption
*/
class BOTAN_DLL TLS_CBC_HMAC_AEAD_Encryption final : public TLS_CBC_HMAC_AEAD_Mode
   {
   public:
      /**
      */
      TLS_CBC_HMAC_AEAD_Encryption(const std::string& cipher_algo,
                                   const size_t cipher_keylen,
                                   const std::string& mac_algo,
                                   const size_t mac_keylen,
                                   bool use_explicit_iv,
                                   bool use_encrypt_then_mac) :
         TLS_CBC_HMAC_AEAD_Encryption(cipher_algo,
                                      cipher_keylen,
                                      mac_algo,
                                      mac_keylen,
                                      use_explicit_iv,
                                      use_encrypt_then_mac)
         {}

      size_t output_length(size_t input_length) const override
         { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

      void finish(secure_vector<byte>& final_block, size_t offset = 0) override;
   };

/**
* TLS_CBC_HMAC_AEAD Decryption
*/
class BOTAN_DLL TLS_CBC_HMAC_AEAD_Decryption final : public TLS_CBC_HMAC_AEAD_Mode
   {
   public:
      /**
      */
      TLS_CBC_HMAC_AEAD_Decryption(const std::string& cipher_algo,
                                   const size_t cipher_keylen,
                                   const std::string& mac_algo,
                                   const size_t mac_keylen,
                                   bool use_explicit_iv,
                                   bool use_encrypt_then_mac) :
         TLS_CBC_HMAC_AEAD_Decryption(cipher_algo,
                                      cipher_keylen,
                                      mac_algo,
                                      mac_keylen,
                                      use_explicit_iv,
                                      use_encrypt_then_mac)
         {}

      size_t output_length(size_t input_length) const override
         {
         BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
         return input_length - tag_size();
         }

      size_t minimum_final_size() const override { return tag_size(); }

      void update(secure_vector<byte>& blocks, size_t offset = 0) override;

      void finish(secure_vector<byte>& final_block, size_t offset = 0) override;

   private:
      void cbc_decrypt_record(byte record_contents[], size_t record_len);
   };

