/*
* TLS CBC Record Handling
* (C) 2012,2013,2014,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rounding.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* TLS_CBC_HMAC_AEAD_Mode Constructor
*/
TLS_CBC_HMAC_AEAD_Mode::TLS_CBC_HMAC_AEAD_Mode(const std::string& cipher_name,
                                               size_t cipher_keylen,
                                               const std::string& mac_name,
                                               size_t mac_keylen,
                                               bool use_explicit_iv,
                                               bool use_encrypt_then_mac) :
   m_cipher_name(cipher_name),
   m_cipher_keylen(cipher_keylen),
   m_mac_name(mac_name),
   m_mac_keylen(mac_keylen)
   {
   m_block_cipher = BlockCipher::create(m_cipher_algo);
   if(!m_block_cipher)
      throw Algorithm_Not_Found(m_cipher_algo);

   m_mac = MessageAuthenticationCode::create("HMAC(" + m_mac_algo + ")");
   if(!m_mac)
      throw Algorithm_Not_Found("HMAC(" + m_mac_algo + ")");

   m_tag_size = m_mac->output_length();
   }

void TLS_CBC_HMAC_AEAD_Mode::clear()
   {
   m_cipher->clear();
   m_mac->clear();
   }

std::string TLS_CBC_HMAC_AEAD_Mode::name() const
   {
   return "TLS_CBC(" + m_cipher_name + "," + m_mac_name + ")";
   }

size_t TLS_CBC_HMAC_AEAD_Mode::update_granularity() const
   {
   return m_cipher->block_size();
   }

bool TLS_CBC_HMAC_AEAD_Mode::valid_nonce_length(size_t nl) const
   {
   return nl == m_cipher->block_size();
   }

Key_Length_Specification TLS_CBC_HMAC_AEAD_Mode::key_spec() const
   {
   return Key_Length_Specification(m_cipher_keylen + m_mac_keylen);
   }

void TLS_CBC_HMAC_AEAD_Mode::key_schedule(const byte key[], size_t keylen)
   {
   m_block_cipher->set_key(cipher_key);
   m_block_size = m_block_cipher->block_size();

   if(version.supports_explicit_cbc_ivs())
      m_iv_size = m_block_size;

   m_mac->set_key(mac_key);
   }

void TLS_CBC_HMAC_AEAD_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   m_ad.assign(ad, ad + ad_len);
   }

secure_vector<byte> TLS_CBC_HMAC_AEAD_Mode::start_raw(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_cbc_state = iv.bits_of();

   return secure_vector<byte>();
   }

void TLS_CBC_HMAC_AEAD_Mode::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   m_msg.insert(m_msg.end(), buf, buf + sz);
   }

void TLS_CBC_HMAC_AEAD_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);

   // now process m_msg
   //buffer += std::make_pair(mac.data(), tag_size());

   const size_t block_size = m_block_size->block_size();

   if(m_uses_encrypt_then_mac == false)
      {
      m_mac->update(cs.format_ad(seq, msg.get_type(), version, static_cast<u16bit>(msg.get_size())));
      m_mac->update(msg.get_data(), msg.get_size());

      const size_t buf_size = round_up(
         m_iv_size + msg.get_size() + mac_size + (block_size ? 1 : 0),
         block_size);

      if(buf_size > MAX_CIPHERTEXT_SIZE)
         throw Internal_Error("Output record is larger than allowed by protocol");

      output.push_back(get_byte(0, static_cast<u16bit>(buf_size)));
      output.push_back(get_byte(1, static_cast<u16bit>(buf_size)));

      const size_t header_size = output.size();

      if(m_iv_size)
         {
         output.resize(output.size() + m_iv_size);
         rng.randomize(&output[output.size() - m_iv_size], m_iv_size);
         }

      output.insert(output.end(), msg.get_data(), msg.get_data() + msg.get_size());

      output.resize(output.size() + mac_size);
      m_mac->final(&output[output.size() - mac_size]);

      if(block_size)
         {
         const size_t pad_val =
            buf_size - (m_iv_size + msg.get_size() + mac_size + 1);

         for(size_t i = 0; i != pad_val + 1; ++i)
            output.push_back(static_cast<byte>(pad_val));
         }

      if(buf_size > MAX_CIPHERTEXT_SIZE)
         throw Internal_Error("Produced ciphertext larger than protocol allows");

      BOTAN_ASSERT_EQUAL(buf_size + header_size, output.size(),
                      "Output buffer is sized properly");

      BOTAN_ASSERT(buf_size % block_size == 0,
                   "Buffer is an even multiple of block size");

      byte* buf = &output[header_size];

      const size_t blocks = buf_size / block_size;

      xor_buf(buf, m_cbc_state.data(), block_size);
      m_block_cipher->encrypt(buf);

      for(size_t i = 1; i < blocks; ++i)
         {
         xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
         m_block_cipher->encrypt(&buf[block_size*i]);
         }

      m_cbc_state.assign(&buf[block_size*(blocks-1)],
                         &buf[block_size*blocks]);
      }
   else
      {
      const size_t enc_size = round_up(
         m_iv_size + msg.get_size() + (block_size ? 1 : 0),
         block_size);

      const size_t buf_size = enc_size + mac_size;

      if(buf_size > MAX_CIPHERTEXT_SIZE)
         throw Internal_Error("Output record is larger than allowed by protocol");

      output.push_back(get_byte<u16bit>(0, buf_size));
      output.push_back(get_byte<u16bit>(1, buf_size));

      const size_t header_size = output.size();

      if(m_iv_size)
         {
         output.resize(output.size() + m_iv_size);
         rng.randomize(&output[output.size() - m_iv_size], m_iv_size);
         }

      output.insert(output.end(), msg.get_data(), msg.get_data() + msg.get_size());

      if(block_size)
         {
         const size_t pad_val =
            enc_size - (m_iv_size + msg.get_size() + 1);

         for(size_t i = 0; i != pad_val + 1; ++i)
            output.push_back(pad_val);
         }

      BOTAN_ASSERT( enc_size % block_size == 0,
                    "Buffer is an even multiple of block size");

      byte* buf = &output[header_size];

      const size_t blocks = enc_size / block_size;

      xor_buf(buf, m_cbc_state.data(), block_size);
      m_block_cipher->encrypt(buf);

      for(size_t i = 1; i < blocks; ++i)
         {
         xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
         m_block_cipher->encrypt(&buf[block_size*i]);
         }

      m_cbc_state.assign(&buf[block_size*(blocks-1)],
                         &buf[block_size*blocks]);

      m_mac->update(cs.format_ad(seq, msg.get_type(), version, enc_size));
      m_mac->update(buf, enc_size);

      output.resize(output.size() + mac_size);
      m_mac->final(&output[output.size() - mac_size]);

      BOTAN_ASSERT_EQUAL(buf_size + header_size, output.size(),
                         "Output buffer is sized properly");
      }
   }

namespace {


/*
* Checks the TLS padding. Returns 0 if the padding is invalid (we
* count the padding_length field as part of the padding size so a
* valid padding will always be at least one byte long), or the length
* of the padding otherwise. This is actually padding_length + 1
* because both the padding and padding_length fields are padding from
* our perspective.
*
* Returning 0 in the error case should ensure the MAC check will fail.
* This approach is suggested in section 6.2.3.2 of RFC 5246.
*/
u16bit tls_padding_check(const byte record[], size_t record_len)
   {
   /*
   * TLS v1.0 and up require all the padding bytes be the same value
   * and allows up to 255 bytes.
   */

   const byte pad_byte = record[(record_len-1)];

   byte pad_invalid = 0;
   for(size_t i = 0; i != record_len; ++i)
      {
      const size_t left = record_len - i - 2;
      const byte delim_mask = CT::is_less<u16bit>(static_cast<u16bit>(left), pad_byte) & 0xFF;
      pad_invalid |= (delim_mask & (record[i] ^ pad_byte));
      }

   u16bit pad_invalid_mask = CT::expand_mask<u16bit>(pad_invalid);
   return CT::select<u16bit>(pad_invalid_mask, 0, pad_byte + 1);
   }

}

void TLS_CBC_HMAC_AEAD_Decryption::cbc_decrypt_record(byte record_contents[], size_t record_len)
   {
   BOTAN_ASSERT(record_len % block_size == 0,
                "Buffer is an even multiple of block size");

   const size_t blocks = record_len / block_size;

   BOTAN_ASSERT(blocks >= 1, "At least one ciphertext block");

   byte* buf = record_contents;

   secure_vector<byte> last_ciphertext(block_size);
   copy_mem(last_ciphertext.data(), buf, block_size);

   bc.decrypt(buf);
   xor_buf(buf, m_cbc_state.data(), block_size);

   secure_vector<byte> last_ciphertext2;

   for(size_t i = 1; i < blocks; ++i)
      {
      last_ciphertext2.assign(&buf[block_size*i], &buf[block_size*(i+1)]);
      bc.decrypt(&buf[block_size*i]);
      xor_buf(&buf[block_size*i], last_ciphertext.data(), block_size);
      std::swap(last_ciphertext, last_ciphertext2);
      }

   m_cbc_state = last_ciphertext;
   }

void TLS_CBC_HMAC_AEAD_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);

   BOTAN_ASSERT(m_msg.size() >= tag_size(), "Have the tag as part of final input");

   if(m_uses_encrypt_then_mac == false)
      {
      // This early exit does not leak info because all the values are public
      if((record_len < m_tag_size + m_iv_size) || (record_len % m_block_cipher->block_size() != 0))
         throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

      CT::poison(record_contents, record_len);

      cbc_decrypt_record(record_contents, record_len);

      // 0 if padding was invalid, otherwise 1 + padding_bytes
      u16bit pad_size = tls_padding_check(record_contents, record_len);

      // This mask is zero if there is not enough room in the packet to get
      // a valid MAC. We have to accept empty packets, since otherwise we
      // are not compatible with the BEAST countermeasure (thus record_len+1).
      const u16bit size_ok_mask = CT::is_lte<u16bit>(static_cast<u16bit>(m_tag_size + pad_size + m_iv_size), static_cast<u16bit>(record_len + 1));
      pad_size &= size_ok_mask;

      CT::unpoison(record_contents, record_len);

      /*
      This is unpoisoned sooner than it should. The pad_size leaks to plaintext_length and
      then to the timing channel in the MAC computation described in the Lucky 13 paper.
      */
      CT::unpoison(pad_size);

      const byte* plaintext_block = &record_contents[m_iv_size];
      const u16bit plaintext_length = static_cast<u16bit>(record_len - m_tag_size - m_iv_size - pad_size);

      m_mac->update(cs.format_ad(record_sequence, record_type, record_version, plaintext_length));
      m_mac->update(plaintext_block, plaintext_length);

      std::vector<byte> mac_buf(m_tag_size);
      m_mac->final(mac_buf.data());

      const size_t mac_offset = record_len - (m_tag_size + pad_size);

      const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), m_tag_size);

      const u16bit ok_mask = size_ok_mask & CT::expand_mask<u16bit>(mac_ok) & CT::expand_mask<u16bit>(pad_size);

      CT::unpoison(ok_mask);

      if(ok_mask)
         {
         output.assign(plaintext_block, plaintext_block + plaintext_length);
         }
      else
         {
         throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
         }
      }
   else
      {
      const size_t enc_size = record_len - m_tag_size;
      // This early exit does not leak info because all the values are public
      if((record_len < m_tag_size + m_iv_size) || ( enc_size % m_block_cipher->block_size() != 0))
         throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

      m_mac->update(cs.format_ad(record_sequence, record_type, record_version, enc_size));
      m_mac->update(record_contents, enc_size);

      std::vector<byte> mac_buf(m_tag_size);
      m_mac->final(mac_buf.data());

      const size_t mac_offset = enc_size;

      const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), m_tag_size);

      if(!mac_ok)
         {
         throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
         }

      cbc_decrypt_record(record_contents, enc_size);

      // 0 if padding was invalid, otherwise 1 + padding_bytes
      u16bit pad_size = tls_padding_check(record_contents, enc_size);

      const byte* plaintext_block = &record_contents[m_iv_size];
      const u16bit plaintext_length = enc_size - m_iv_size - pad_size;

      output.assign(plaintext_block, plaintext_block + plaintext_length);
      }
   }

}
