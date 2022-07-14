/*
 *  Client interface for local Tuya device access
 *
 *  Copyright 2022 - Martin Walker - https://github.com/marsjupiter1/ArduinoTuya
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 */

#define DEBUG
#define SOCKET_TIMEOUT_SECS 2
#include <stdio.h>
#include "TuyaLocal.hpp"
#include "mbedtls/aes.h"
#include "MD5.h"
#include <netdb.h>

#include <sstream>
#include <thread>
#include <chrono>
#include <Arduino_CRC32.h>
#include <errno.h>
#include <base64.hpp>
/* ... */
Arduino_CRC32 Crc32;

#ifdef DEBUG
#include <iostream>

#endif

tuyaLocal::tuyaLocal(String host, String device, String key, const char *protocol, int port)
{
	m_protocol = protocol;
	client = NULL;
	m_hostname = host;
	m_portnumber = port;
	m_key = key;
	m_device_id = device;
}

tuyaLocal::~tuyaLocal()
{
	disconnect();
}

#define MAX_BUFFER_SIZE 500
String tuyaLocal::getDps()
{

	unsigned char message_buffer[MAX_BUFFER_SIZE];
	long currenttime = time(NULL);
	String payload;

	payload = String("{\"gwId\":\"") + m_device_id + String("\",\"devId\":\"") + m_device_id + String("\",\"uid\":\"") + m_device_id + String("\",\"t\":\"") + String(currenttime) + String("\"}");

	int payload_len = BuildTuyaMessage(message_buffer, TUYA_DP_QUERY, payload);

	int numbytes = send(message_buffer, payload_len);
	if (numbytes > 0)
	{

		numbytes = receive(message_buffer, MAX_BUFFER_SIZE - 1);

		String tuyaresponse = DecodeTuyaMessage(message_buffer, numbytes);
		return tuyaresponse;
	}
	return "";
}


int tuyaLocal::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, String &payload, bool encrypt)
{
#ifdef DEBUG
	std::cout << "protocol: "<< m_protocol.c_str()<< "\n";
	std::cout << "dbg: payload: ";
	std::cout << payload.c_str();
	std::cout << "\n";
#endif
	// pad payload to a multiple of 16 bytes
	int payload_len = (int)payload.length();
	if (payload_len > 0 && (m_protocol != "3.1" || encrypt))
	{
		uint8_t padding = 16 - (payload_len % 16);
		for (int i = 0; i < padding; i++)
		{
			payload += (char)padding;
		}
		payload_len = (int)payload.length();

	}

	unsigned char ecb[500];
	memcpy((void *)ecb, (void *)payload.c_str(), payload_len+1);
	if (encrypt || m_protocol != "3.1")
	{

		for (int i = 0; i < payload_len / 16; ++i)
		{
			mbedtls_aes_context aes;
			mbedtls_aes_init(&aes);
			mbedtls_aes_setkey_enc(&aes, (const unsigned char *)m_key.c_str(), 128 );
			mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char *)payload.c_str() + i * 16, &ecb[i * 16]);
			mbedtls_aes_free(&aes);
		}

#ifdef DEBUG
		std::cout << "dbg: encrypted payload: ";
		for (int i = 0; i < payload_len; ++i)
			printf("%.2x", (uint8_t)ecb[i]);
		std::cout << "\n";
#endif
	}

	bcopy(MESSAGE_SEND_HEADER, (char *)&buffer[0], sizeof(MESSAGE_SEND_HEADER));

	int payload_pos = (int)sizeof(MESSAGE_SEND_HEADER);
	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		if (m_protocol != "3.1")
		{
			// add the protocol 3.3 secondary header
			bcopy(PROTOCOL_33_HEADER, (char *)&buffer[payload_pos], sizeof(PROTOCOL_33_HEADER));
			payload_pos += sizeof(PROTOCOL_33_HEADER);
		}
	}

	unsigned char ecb64[200]; 
	if (m_protocol == "3.1" && encrypt)
	{
		
		payload_len = encode_base64( (unsigned char *)&ecb[0], payload_len,ecb64);
		
		// add 3.1 info
		std::cout << "(ecb64) base64 encoded: "<<ecb64 <<"\n";
		String premd5 = String("data=")+String((char *)ecb64);
		
		premd5 += "||lpv=3.1||" + m_key;
		std::cout << "(ecb64) 3.1md5 string: "<< premd5.c_str()<<"\n";
		unsigned char *hash = MD5::make_hash((char *)premd5.c_str());
		// generate the digest (hex encoding) of our hash
		char *md5str = MD5::make_digest(hash, 16);
		md5str[24]='\0';
		String md5mid = (char *)&md5str[8];
		
		String header = String("3.1") + md5mid;
		std::cout << "header to "<<payload_pos<< " :"<<header.c_str()<<"\n";
		bcopy(header.c_str(), &buffer[payload_pos], header.length());
		payload_pos += header.length();
		std::cout << "data header length: "<<header.length()<< "\n";
		free(hash);
		free(md5str);
		strcpy((char *)ecb,(char *)ecb64);
	}else{
		std::cout << "dbg: 3.1 payload: ";
		std::cout <<  ecb << "\n";
	}
	std::cout << "payload length: "<<payload_len<< "\n";
	std::cout << "payload pos: "<<payload_pos<< "\n";
	
	bcopy(ecb, (char *)&buffer[payload_pos], payload_len);
	bcopy(MESSAGE_SEND_TRAILER, (char *)&buffer[payload_pos + payload_len], sizeof(MESSAGE_SEND_TRAILER));

	// insert command code in int32 @msg[8] (single byte value @msg[11])
	buffer[11] = command;
	// insert message size in int32 @msg[12] doesn't include the header
	buffer[14] = ((payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)-sizeof(MESSAGE_SEND_HEADER) ) & 0xFF00) >> 8;
	buffer[15] = (payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)-sizeof(MESSAGE_SEND_HEADER) ) & 0xFF;

	// calculate CRC

	unsigned long crc = Crc32.calc(buffer, payload_pos + payload_len) & 0xFFFFFFFF;
	// overwrite first 4 bytes of the trailer
	buffer[payload_pos + payload_len] = (crc & 0xFF000000) >> 24;
	buffer[payload_pos + payload_len + 1] = (crc & 0x00FF0000) >> 16;
	buffer[payload_pos + payload_len + 2] = (crc & 0x0000FF00) >> 8;
	buffer[payload_pos + payload_len + 3] = crc & 0x000000FF;

#ifdef DEBUG
	std::cout << "dbg: complete message: ";
	for (int i = 0; i < (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";	
	for (int i = 16; i < (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)); ++i)
		printf("%c", (uint8_t)buffer[i]);	
	std::cout << "\n";
#endif

	return (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER));
}


String tuyaLocal::DecodeTuyaMessage(unsigned char *buffer, const int size)
{
	String result;

	int message_start = 0;
	while (message_start < size)
	{
		unsigned char *message = &buffer[message_start];
		unsigned char *encryptedpayload = &message[sizeof(MESSAGE_SEND_HEADER) + sizeof(int)];
		int message_size = (int)((uint8_t)message[15] + ((uint8_t)message[14] << 8) + sizeof(MESSAGE_SEND_HEADER));

		// verify crc
		unsigned int crc_sent = ((uint8_t)message[message_size - 8] << 24) + ((uint8_t)message[message_size - 7] << 16) + ((uint8_t)message[message_size - 6] << 8) + (uint8_t)message[message_size - 5];

		unsigned int crc = Crc32.calc(message, message_size - 8) & 0xFFFFFFFF;

		if (crc == crc_sent)
		{
			int payload_len = (int)(message_size - sizeof(MESSAGE_SEND_HEADER) - sizeof(int) - sizeof(MESSAGE_SEND_TRAILER));
			// test for presence of secondary protocol 3.3 header (odd message size)
			if ((message[15] & 0x1) && (encryptedpayload[0] == '3') && (encryptedpayload[1] == '.') && (encryptedpayload[2] == '3'))
			{
				m_protocol = "3.3";
				encryptedpayload += 15;
				payload_len -= 15;
			}
			else
			{
				m_protocol = "3.1";
			}
			unsigned char *out = (unsigned char *)calloc(payload_len + 1, sizeof(char));
			// AES aes(AESKeyLength::AES_128);
			std::cout << "payload length: " << payload_len << "\n";
			if (payload_len > 0)
			{
				if (m_protocol == "3.1")
				{
					bcopy(encryptedpayload, out, payload_len);
				}
				else
				{
					mbedtls_aes_context aes;

					mbedtls_aes_init(&aes);
					mbedtls_aes_setkey_dec(&aes, (const unsigned char *)m_key.c_str(), m_key.length() * 8);
					for (int i = 0; i < payload_len / 16; ++i)
					{
						mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char *)(encryptedpayload + i * 16), out + i * 16);
					}
					mbedtls_aes_free(&aes);

					//  trim padding chars from decrypted payload
					uint8_t padding = out[payload_len - 1];
					if (padding <= 16)
					{
						out[payload_len - padding] = 0;
					}
				}
			}
			result += String((const char *)out);
			std::cout << "recieved msg: " << result.c_str() << "\n";
			free(out);
		}
		else
			result += "{\"msg\":\"crc error\"}";

		message_start += message_size;
	}
	return result;
}

String tuyaLocal::send_heartbeat()
{
	return "";
	std::cout << "heartbeat\n";
	unsigned char message_buffer[200];
	String payload;
	int payload_len = BuildTuyaMessage(message_buffer, TUYA_HEART_BEAT, payload);
	send(message_buffer, payload_len);
	int bytes = receive(message_buffer, 200);
	return DecodeTuyaMessage(message_buffer, bytes);
}

bool tuyaLocal::ConnectToDevice(uint8_t retries)
{
	disconnect();
	client = new WiFiClient();

	m_retries = retries;
	struct timeval tv;
	tv.tv_sec = SOCKET_TIMEOUT_SECS;
	tv.tv_usec = 0;
	int flag = 1;
	for (auto i = 0; i < retries; i++)
	{
		int res = client->connect(m_hostname.c_str(), m_portnumber);
		if (res == 1)
		{
			// client.setSocketOption( SO_RCVTIMEO, ( char*)&tv, sizeof tv);
			// client.setSocketOption(  SO_KEEPALIVE, ( char * )&flag, sizeof flag);
			//   client.setSocketOption(  SO_REUSEADDR, ( char *)&flag, sizeof(flag));

			client->setNoDelay(true);
			// send_heartbeat();
			// client.setTimeout(10);
			return true;
		}

#ifdef DEBUG

		std::cout << m_hostname.c_str() << ":" << m_portnumber << " Connect error:" << res << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
#endif
	}
	// std::this_thread::sleep_for(std::chrono::milliseconds(1000));

	return false;
}

int tuyaLocal::send(unsigned char *buffer, const unsigned int size)
{
	// reconnect();
	int err;
	std::cout << "try and send\n";
	// err = client.write(buffer, size+ sizeof(MESSAGE_SEND_HEADER) + sizeof(MESSAGE_SEND_TRAILER));
	err = client->write(buffer, size);

	std::cout << "sent:" << err << " of " << size << "\n";
	if (err < size)
	{
		reconnect();
		err = client->write(buffer, size);
		std::cout << "resent:" << err << "\n";
	}
	return err;
}

int tuyaLocal::receive(unsigned char *buffer, const unsigned int maxsize, const unsigned int minsize)
{
	int index = 0;
	int prefix_index = 0;
	int trailer_index = 4;
	int tries = 0;
	int total = 0;
	std::cout << "recieve\n";
	// send_heartbeat();
	while (trailer_index < 8 && tries++ < 10 && index <= minsize)
	{
		if (!client->connected())
		{
			std::cout << "client not connected\n";
			break;
		}
		int numbytes = client->available();
		std::cout << "available:" << numbytes << "\n";
		for (auto i = 0; i < numbytes; i++)
		{
			total++;
			char c = client->read();
			// printf("%d: %.2x :", index, (uint8_t)c);
			;
			if (prefix_index == 4 && trailer_index < 8 && c == MESSAGE_SEND_TRAILER[trailer_index])
			{
				trailer_index++;
				// std::cout << "t" << trailer_index << "\n";
			}
			else
			{
				trailer_index = 4;
			}
			if (prefix_index < 4 && c != MESSAGE_SEND_HEADER[prefix_index])
			{
				index = 0;
				prefix_index = 0;
				// std::cout << "x";
			}
			else
			{
				// std::cout << "v" << (prefix_index + 1) << "\n";
				buffer[index] = c;
				index++;
				if (prefix_index < 4)
				{
					prefix_index++;
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	std::cout << "read:" << total << " recieved: " << index << "\n";
	return (int)index;
}

void tuyaLocal::disconnect()
{
	if (client)
	{
		delete client;
	}
	client = NULL;
}

bool tuyaLocal::reconnect()
{
	return ConnectToDevice(m_retries);
}
