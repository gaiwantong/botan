/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGES_H__
#define BOTAN_TLS_MESSAGES_H__

#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/bigint.h>
#include <botan/x509cert.h>
#include <vector>
#include <string>

namespace Botan {

class Credentials_Manager;

#if defined(BOTAN_HAS_SRP6)
class SRP6_Server_Session;
#endif

namespace TLS {

class Session;
class Handshake_IO;

std::vector<byte> make_hello_random(RandomNumberGenerator& rng,
                                    const Policy& policy);

/**
* DTLS Hello Verify Request
*/
class Hello_Verify_Request final : public Handshake_Message
   {
   public:
      std::vector<byte> serialize() const override;
      Handshake_Type type() const override { return HELLO_VERIFY_REQUEST; }

      std::vector<byte> cookie() const { return m_cookie; }

      explicit Hello_Verify_Request(const std::vector<byte>& buf);

      Hello_Verify_Request(const std::vector<byte>& client_hello_bits,
                           const std::string& client_identity,
                           const SymmetricKey& secret_key);
   private:
      std::vector<byte> m_cookie;
   };

/**
* Client Hello Message
*/
class Client_Hello final : public Handshake_Message
   {
   public:
      class Settings
      {
          public:
              Settings(const Protocol_Version version,
                       const std::string& hostname = "",
                       const std::string& srp_identifier = "")
                  : m_new_session_version(version),
                    m_hostname(hostname),
                    m_srp_identifier(srp_identifier) {};

              const Protocol_Version protocol_version() const { return m_new_session_version; };
              const std::string& hostname() const { return m_hostname; };
              const std::string& srp_identifier() const { return m_srp_identifier; }

          private:
              const Protocol_Version m_new_session_version;
              const std::string m_hostname;
              const std::string m_srp_identifier;
      };

      Handshake_Type type() const override { return CLIENT_HELLO; }

      Protocol_Version version() const { return m_version; }

      const std::vector<byte>& random() const { return m_random; }

      const std::vector<byte>& session_id() const { return m_session_id; }

      std::vector<u16bit> ciphersuites() const { return m_suites; }

      std::vector<byte> compression_methods() const { return m_comp_methods; }

      bool offered_suite(u16bit ciphersuite) const;

      bool sent_fallback_scsv() const;

      std::vector<std::pair<std::string, std::string>> supported_algos() const
         {
         if(Signature_Algorithms* sigs = m_extensions.get<Signature_Algorithms>())
            return sigs->supported_signature_algorthms();
         return std::vector<std::pair<std::string, std::string>>();
         }

      std::vector<std::string> supported_ecc_curves() const
         {
         if(Supported_Elliptic_Curves* ecc = m_extensions.get<Supported_Elliptic_Curves>())
            return ecc->curves();
         return std::vector<std::string>();
         }

      std::string sni_hostname() const
         {
         if(Server_Name_Indicator* sni = m_extensions.get<Server_Name_Indicator>())
            return sni->host_name();
         return "";
         }

#if defined(BOTAN_HAS_SRP6)
      std::string srp_identifier() const
         {
         if(SRP_Identifier* srp = m_extensions.get<SRP_Identifier>())
            return srp->identifier();
         return "";
         }
#endif

      bool secure_renegotiation() const
         {
         return m_extensions.has<Renegotiation_Extension>();
         }

      std::vector<byte> renegotiation_info() const
         {
         if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
            return reneg->renegotiation_info();
         return std::vector<byte>();
         }

      bool supports_session_ticket() const
         {
         return m_extensions.has<Session_Ticket>();
         }

      std::vector<byte> session_ticket() const
         {
         if(Session_Ticket* ticket = m_extensions.get<Session_Ticket>())
            return ticket->contents();
         return std::vector<byte>();
         }

      bool supports_alpn() const
         {
         return m_extensions.has<Application_Layer_Protocol_Notification>();
         }

      bool supports_extended_master_secret() const
         {
         return m_extensions.has<Extended_Master_Secret>();
         }

      bool supports_encrypt_then_mac() const
         {
         return m_extensions.has<Encrypt_then_MAC>();
         }

      std::vector<std::string> next_protocols() const
         {
         if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
            return alpn->protocols();
         return std::vector<std::string>();
         }

      std::vector<u16bit> srtp_profiles() const
         {
         if(SRTP_Protection_Profiles* srtp = m_extensions.get<SRTP_Protection_Profiles>())
            return srtp->profiles();
         return std::vector<u16bit>();
         }

      void update_hello_cookie(const Hello_Verify_Request& hello_verify);

      std::set<Handshake_Extension_Type> extension_types() const
         { return m_extensions.extension_types(); }

      Client_Hello(Handshake_IO& io,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   RandomNumberGenerator& rng,
                   const std::vector<byte>& reneg_info,
                   const Client_Hello::Settings& client_settings,
                   const std::vector<std::string>& next_protocols);

      Client_Hello(Handshake_IO& io,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   RandomNumberGenerator& rng,
                   const std::vector<byte>& reneg_info,
                   const Session& resumed_session,
                   const std::vector<std::string>& next_protocols);

      explicit Client_Hello(const std::vector<byte>& buf);

   private:
      std::vector<byte> serialize() const override;

      Protocol_Version m_version;
      std::vector<byte> m_session_id;
      std::vector<byte> m_random;
      std::vector<u16bit> m_suites;
      std::vector<byte> m_comp_methods;
      std::vector<byte> m_hello_cookie; // DTLS only

      Extensions m_extensions;
   };

/**
* Server Hello Message
*/
class Server_Hello final : public Handshake_Message
   {
   public:
      class Settings
      {
          public:
              Settings(const std::vector<byte> new_session_id,
                       Protocol_Version new_session_version,
                       u16bit ciphersuite,
                       byte compression,
                       bool offer_session_ticket)
                  : m_new_session_id(new_session_id),
                    m_new_session_version(new_session_version),
                    m_ciphersuite(ciphersuite),
                    m_compression(compression),
                    m_offer_session_ticket(offer_session_ticket) {};

              const std::vector<byte>& session_id() const { return m_new_session_id; };
              Protocol_Version protocol_version() const { return m_new_session_version; };
              u16bit ciphersuite() const { return m_ciphersuite; };
              byte compression() const { return m_compression; }
              bool offer_session_ticket() const { return m_offer_session_ticket; }

          private:
              const std::vector<byte> m_new_session_id;
              Protocol_Version m_new_session_version;
              u16bit m_ciphersuite;
              byte m_compression;
              bool m_offer_session_ticket;
      };


      Handshake_Type type() const override { return SERVER_HELLO; }

      Protocol_Version version() const { return m_version; }

      const std::vector<byte>& random() const { return m_random; }

      const std::vector<byte>& session_id() const { return m_session_id; }

      u16bit ciphersuite() const { return m_ciphersuite; }

      byte compression_method() const { return m_comp_method; }

      bool secure_renegotiation() const
         {
         return m_extensions.has<Renegotiation_Extension>();
         }

      std::vector<byte> renegotiation_info() const
         {
         if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
            return reneg->renegotiation_info();
         return std::vector<byte>();
         }

      bool supports_extended_master_secret() const
         {
         return m_extensions.has<Extended_Master_Secret>();
         }

      bool supports_encrypt_then_mac() const
         {
         return m_extensions.has<Encrypt_then_MAC>();
         }

      bool supports_session_ticket() const
         {
         return m_extensions.has<Session_Ticket>();
         }

      u16bit srtp_profile() const
         {
         if(auto srtp = m_extensions.get<SRTP_Protection_Profiles>())
            {
            auto prof = srtp->profiles();
            if(prof.size() != 1 || prof[0] == 0)
               throw Decoding_Error("Server sent malformed DTLS-SRTP extension");
            return prof[0];
            }

         return 0;
         }

      std::string next_protocol() const
         {
         if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
            return alpn->single_protocol();
         return "";
         }

      std::set<Handshake_Extension_Type> extension_types() const
         { return m_extensions.extension_types(); }

      Server_Hello(Handshake_IO& io,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   RandomNumberGenerator& rng,
                   const std::vector<byte>& secure_reneg_info,
                   const Client_Hello& client_hello,
                   const Server_Hello::Settings& settings,
                   const std::string next_protocol);

      Server_Hello(Handshake_IO& io,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   RandomNumberGenerator& rng,
                   const std::vector<byte>& secure_reneg_info,
                   const Client_Hello& client_hello,
                   Session& resumed_session,
                   bool offer_session_ticket,
                   const std::string& next_protocol);

      explicit Server_Hello(const std::vector<byte>& buf);
   private:
      std::vector<byte> serialize() const override;

      Protocol_Version m_version;
      std::vector<byte> m_session_id, m_random;
      u16bit m_ciphersuite;
      byte m_comp_method;

      Extensions m_extensions;
   };

/**
* Client Key Exchange Message
*/
class Client_Key_Exchange final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CLIENT_KEX; }

      const secure_vector<byte>& pre_master_secret() const
         { return m_pre_master; }

      Client_Key_Exchange(Handshake_IO& io,
                          Handshake_State& state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          const Public_Key* server_public_key,
                          const std::string& hostname,
                          RandomNumberGenerator& rng);

      Client_Key_Exchange(const std::vector<byte>& buf,
                          const Handshake_State& state,
                          const Private_Key* server_rsa_kex_key,
                          Credentials_Manager& creds,
                          const Policy& policy,
                          RandomNumberGenerator& rng);

   private:
      std::vector<byte> serialize() const override
         { return m_key_material; }

      std::vector<byte> m_key_material;
      secure_vector<byte> m_pre_master;
   };

/**
* Certificate Message
*/
class Certificate final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CERTIFICATE; }
      const std::vector<X509_Certificate>& cert_chain() const { return m_certs; }

      size_t count() const { return m_certs.size(); }
      bool empty() const { return m_certs.empty(); }

      Certificate(Handshake_IO& io,
                  Handshake_Hash& hash,
                  const std::vector<X509_Certificate>& certs);

      explicit Certificate(const std::vector<byte>& buf, const Policy &policy);
   private:
      std::vector<byte> serialize() const override;

      std::vector<X509_Certificate> m_certs;
   };

/**
* Certificate Request Message
*/
class Certificate_Req final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CERTIFICATE_REQUEST; }

      const std::vector<std::string>& acceptable_cert_types() const
         { return m_cert_key_types; }

      std::vector<X509_DN> acceptable_CAs() const { return m_names; }

      std::vector<std::pair<std::string, std::string> > supported_algos() const
         { return m_supported_algos; }

      Certificate_Req(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      const std::vector<X509_DN>& allowed_cas,
                      Protocol_Version version);

      Certificate_Req(const std::vector<byte>& buf,
                      Protocol_Version version);
   private:
      std::vector<byte> serialize() const override;

      std::vector<X509_DN> m_names;
      std::vector<std::string> m_cert_key_types;

      std::vector<std::pair<std::string, std::string> > m_supported_algos;
   };

/**
* Certificate Verify Message
*/
class Certificate_Verify final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return CERTIFICATE_VERIFY; }

      /**
      * Check the signature on a certificate verify message
      * @param cert the purported certificate
      * @param state the handshake state
      */
      bool verify(const X509_Certificate& cert,
                  const Handshake_State& state,
                  const Policy& policy) const;

      Certificate_Verify(Handshake_IO& io,
                         Handshake_State& state,
                         const Policy& policy,
                         RandomNumberGenerator& rng,
                         const Private_Key* key);

      Certificate_Verify(const std::vector<byte>& buf,
                         Protocol_Version version);
   private:
      std::vector<byte> serialize() const override;

      std::string m_sig_algo; // sig algo used to create signature
      std::string m_hash_algo; // hash used to create signature
      std::vector<byte> m_signature;
   };

/**
* Finished Message
*/
class Finished final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return FINISHED; }

      std::vector<byte> verify_data() const
         { return m_verification_data; }

      bool verify(const Handshake_State& state,
                  Connection_Side side) const;

      Finished(Handshake_IO& io,
               Handshake_State& state,
               Connection_Side side);

      explicit Finished(const std::vector<byte>& buf);
   private:
      std::vector<byte> serialize() const override;

      std::vector<byte> m_verification_data;
   };

/**
* Hello Request Message
*/
class Hello_Request final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return HELLO_REQUEST; }

      explicit Hello_Request(Handshake_IO& io);
      explicit Hello_Request(const std::vector<byte>& buf);
   private:
      std::vector<byte> serialize() const override;
   };

/**
* Server Key Exchange Message
*/
class Server_Key_Exchange final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return SERVER_KEX; }

      const std::vector<byte>& params() const { return m_params; }

      bool verify(const Public_Key& server_key,
                  const Handshake_State& state,
                  const Policy& policy) const;

      // Only valid for certain kex types
      const Private_Key& server_kex_key() const;

#if defined(BOTAN_HAS_SRP6)
      // Only valid for SRP negotiation
      SRP6_Server_Session& server_srp_params() const
         {
         BOTAN_ASSERT_NONNULL(m_srp_params);
         return *m_srp_params;
         }
#endif

      Server_Key_Exchange(Handshake_IO& io,
                          Handshake_State& state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          RandomNumberGenerator& rng,
                          const Private_Key* signing_key = nullptr);

      Server_Key_Exchange(const std::vector<byte>& buf,
                          const std::string& kex_alg,
                          const std::string& sig_alg,
                          Protocol_Version version);

      ~Server_Key_Exchange();
   private:
      std::vector<byte> serialize() const override;

#if defined(BOTAN_HAS_SRP6)
      std::unique_ptr<SRP6_Server_Session> m_srp_params;
#endif
      std::unique_ptr<Private_Key> m_kex_key;

      std::vector<byte> m_params;

      std::string m_sig_algo; // sig algo used to create signature
      std::string m_hash_algo; // hash used to create signature
      std::vector<byte> m_signature;
   };

/**
* Server Hello Done Message
*/
class Server_Hello_Done final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return SERVER_HELLO_DONE; }

      Server_Hello_Done(Handshake_IO& io, Handshake_Hash& hash);
      explicit Server_Hello_Done(const std::vector<byte>& buf);
   private:
      std::vector<byte> serialize() const override;
   };

/**
* New Session Ticket Message
*/
class New_Session_Ticket final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return NEW_SESSION_TICKET; }

      u32bit ticket_lifetime_hint() const { return m_ticket_lifetime_hint; }
      const std::vector<byte>& ticket() const { return m_ticket; }

      New_Session_Ticket(Handshake_IO& io,
                         Handshake_Hash& hash,
                         const std::vector<byte>& ticket,
                         u32bit lifetime);

      New_Session_Ticket(Handshake_IO& io,
                         Handshake_Hash& hash);

      explicit New_Session_Ticket(const std::vector<byte>& buf);
   private:
      std::vector<byte> serialize() const override;

      u32bit m_ticket_lifetime_hint = 0;
      std::vector<byte> m_ticket;
   };

/**
* Change Cipher Spec
*/
class Change_Cipher_Spec final : public Handshake_Message
   {
   public:
      Handshake_Type type() const override { return HANDSHAKE_CCS; }

      std::vector<byte> serialize() const override
         { return std::vector<byte>(1, 1); }
   };

}

}

#endif
