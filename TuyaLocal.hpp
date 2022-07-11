/*
 *  Client interface for local Tuya device access
 *
 *  Copyright 2022 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#define DEBUG
#define SOCKET_TIMEOUT_SECS 15
#include <stdio.h>
#include "TuyaLocal.hpp"
#include "mbedtls/aes.h"
#include "aes.hpp"
//#include "TI_aes_128_encr_only.h"
#include <netdb.h>
//#include <zlib.h>
#include <sstream>
#include <thread>
#include <chrono>
#include <Arduino_CRC32.h>
#include <errno.h>
/* ... */
Arduino_CRC32 Crc32;

#ifdef DEBUG
#include <iostream>

#endif

tuyaLocal::tuyaLocal()
{
}

tuyaLocal::~tuyaLocal()
{
	disconnect();
}

#if 0
int tuyaLocal::BuildTuyaMessage(unsigned char *buffer, const uint8_t command,String payload)
{
	// pad payload to a multiple of 16 bytes
	int payload_len = (int)payload.length();
	uint8_t padding = 16 - (payload_len % 16);
	for (int i = 0; i < padding; i++){
		payload += (char)padding;
	}	
	payload_len = (int)payload.length();

#ifdef DEBUG
	std::cout << "dbg: padded payload (len=" << payload_len << "): ";
	for (int i = 0; i < payload_len; ++i)
		printf("%.2x", (uint8_t)payload[i]);
	std::cout << "\n";
#endif

	bcopy(MESSAGE_SEND_HEADER, (char *)&buffer[0], sizeof(MESSAGE_SEND_HEADER));

	int payload_pos = (int)sizeof(MESSAGE_SEND_HEADER);
	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		// add the protocol 3.3 secondary header
		bcopy(PROTOCOL_33_HEADER, (char *)&buffer[payload_pos], sizeof(PROTOCOL_33_HEADER));
		payload_pos += sizeof(PROTOCOL_33_HEADER);
	}
	bcopy(payload.c_str(), (char *)&buffer[payload_pos], payload_len);
	bcopy(MESSAGE_SEND_TRAILER, (char *)&buffer[payload_pos + payload_len], sizeof(MESSAGE_SEND_TRAILER));

	// insert command code in int32 @msg[8] (single byte value @msg[11])
	buffer[11] = command;
	// insert message size in int32 @msg[12]
	buffer[14] = ((payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER) - sizeof(MESSAGE_SEND_HEADER)) & 0xFF00) >> 8;
	buffer[15] = (payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER) - sizeof(MESSAGE_SEND_HEADER)) & 0xFF;

	// calculate CRC

	unsigned long crc = Crc32.calc(buffer, payload_pos + payload_len) & 0xFFFFFFFF;
	buffer[payload_pos + payload_len] = (crc & 0xFF000000) >> 24;
	buffer[payload_pos + payload_len + 1] = (crc & 0x00FF0000) >> 16;
	buffer[payload_pos + payload_len + 2] = (crc & 0x0000FF00) >> 8;
	buffer[payload_pos + payload_len + 3] = crc & 0x000000FF;

#ifdef DEBUG
	std::cout << "dbg: complete message: ";
	for (int i = 0; i < (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER));
}
#endif
#if 1
int tuyaLocal::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, String &payload, const String &encryption_key)
{
#ifdef DEBUG
	std::cout << "dbg: payload: ";
	std::cout << payload.c_str();
	std::cout << "\n";
#endif
	// pad payload to a multiple of 16 bytes
	int payload_len = (int)payload.length();
	uint8_t padding = 16 - (payload_len % 16);
	for (int i = 0; i < padding; i++){
		payload += (char)padding;
	}	
	payload_len = (int)payload.length();
#ifdef DEBUG
	std::cout << "dbg: padded payload: ";
	std::cout << payload.c_str();
	std::cout << "\n";
#endif
#ifdef DEBUG
	std::cout << "dbg: padded payload (len=" << payload_len << "): ";
	for (int i = 0; i < payload_len; ++i)
		printf("%.2x", (uint8_t)payload[i]);
	std::cout << "\n";
#endif
	unsigned char out[500];
	// AES aes(AESKeyLength::AES_128);
	for (int i = 0; i < payload_len/16; ++i)
    {
		mbedtls_aes_context aes;
		mbedtls_aes_init( &aes );
		mbedtls_aes_setkey_enc(&aes, (const unsigned char *)encryption_key.c_str(), 128/*encryption_key.length() * 8*/);
		// unsigned char *out = aes.EncryptECB((unsigned char*)payload.c_str(), payload_len, (unsigned char*)encryption_key.c_str());
		mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char *)payload.c_str()+i*16, &out[i*16]);
		mbedtls_aes_free(&aes);
	}	
#ifdef DEBUG
	std::cout << "dbg: encrypted payload: ";
	for (int i = 0; i < payload_len; ++i)
		printf("%.2x", (uint8_t)out[i]);
	std::cout << "\n";
#endif
	struct AES_ctx ctx;
	memcpy((void *)out,(void *)payload.c_str(),payload_len);
    AES_init_ctx(&ctx, (const unsigned char *)encryption_key.c_str());	
	for (int i = 0; i < payload_len/16; ++i)
    {
 		AES_ECB_encrypt(&ctx,  out+(16*i));
	}
#ifdef DEBUG
	std::cout << "dbg: encrypted payload: ";
	for (int i = 0; i < payload_len; ++i)
		printf("%.2x", (uint8_t)out[i]);
	std::cout << "\n";
#endif

	bcopy(MESSAGE_SEND_HEADER, (char *)&buffer[0], sizeof(MESSAGE_SEND_HEADER));

	int payload_pos = (int)sizeof(MESSAGE_SEND_HEADER);
	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		// add the protocol 3.3 secondary header
		bcopy(PROTOCOL_33_HEADER, (char *)&buffer[payload_pos], sizeof(PROTOCOL_33_HEADER));
		payload_pos += sizeof(PROTOCOL_33_HEADER);
	}
	bcopy(out, (char *)&buffer[payload_pos], payload_len);
	bcopy(MESSAGE_SEND_TRAILER, (char *)&buffer[payload_pos + payload_len], sizeof(MESSAGE_SEND_TRAILER));

	// insert command code in int32 @msg[8] (single byte value @msg[11])
	buffer[11] = command;
	// insert message size in int32 @msg[12]
	buffer[14] = ((payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER) - sizeof(MESSAGE_SEND_HEADER)) & 0xFF00) >> 8;
	buffer[15] = (payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER) - sizeof(MESSAGE_SEND_HEADER)) & 0xFF;

	// calculate CRC

	unsigned long crc = Crc32.calc(buffer, payload_pos + payload_len) & 0xFFFFFFFF;
	buffer[payload_pos + payload_len] = (crc & 0xFF000000) >> 24;
	buffer[payload_pos + payload_len + 1] = (crc & 0x00FF0000) >> 16;
	buffer[payload_pos + payload_len + 2] = (crc & 0x0000FF00) >> 8;
	buffer[payload_pos + payload_len + 3] = crc & 0x000000FF;

#ifdef DEBUG
	std::cout << "dbg: complete message: ";
	for (int i = 0; i < (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER));
}
#endif

String tuyaLocal::DecodeTuyaMessage(unsigned char *buffer, const int size, const String &encryption_key)
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
				encryptedpayload += 15;
				payload_len -= 15;
			}
			unsigned char *out = (unsigned char *)calloc(payload_len + 1, sizeof(char));
			// AES aes(AESKeyLength::AES_128);
			mbedtls_aes_context aes;

			mbedtls_aes_init(&aes);
			mbedtls_aes_setkey_dec(&aes, (const unsigned char *)encryption_key.c_str(), encryption_key.length() * 8);
			mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char *)encryptedpayload, out);
			mbedtls_aes_free(&aes);
			// unsigned char *out = aes.DecryptECB(encryptedpayload, payload_len, (unsigned char*)encryption_key.c_str());
			//  trim padding chars from decrypted payload
			uint8_t padding = out[payload_len - 1];
			if (padding <= 16)
				out[payload_len - padding] = 0;

			result += String((const char *)out);
			std::cout << "recieved msg: "<< result<<"\n";
			free(out);
		}
		else
			result += "{\"msg\":\"crc error\"}";

		message_start += message_size;
	}
	return result;
}

#if 0
void  tuyaLocal::send_heartbeat(){
	std::cout << "heartbeat\n";
	unsigned char message_buffer[200];
	int payload_len = BuildTuyaMessage(message_buffer, TUYA_HEART_BEAT, String(""));
	send(message_buffer,payload_len);
}
#endif

bool tuyaLocal::ConnectToDevice(const String &hostname, const int portnumber, uint8_t retries)
{
	m_hostname = hostname;
	m_portnumber = portnumber;
	m_retries = retries;
	struct timeval tv;
	tv.tv_sec = SOCKET_TIMEOUT_SECS;
	tv.tv_usec = 0;
	int flag =1;
	for (auto i =0 ;i <retries;i++){
	int res = client.connect(hostname.c_str(), portnumber);
	if (res == 1){
		//client.setSocketOption( SO_RCVTIMEO, ( char*)&tv, sizeof tv);
	    client.setSocketOption(  SO_KEEPALIVE, ( char * )&flag, sizeof flag);
        //  client.setSocketOption(  SO_REUSEADDR, ( char *)&flag, sizeof(flag));
  
		  client.setNoDelay(true);
		  //send_heartbeat();
		  //client.setTimeout(10);
		return true;
	}
		
#ifdef DEBUG
	
		std::cout << hostname.c_str() <<":"<<portnumber << " Connect error:"<< res<<"\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
#endif
	}
	//std::this_thread::sleep_for(std::chrono::milliseconds(1000));

return false;
}

int tuyaLocal::send(unsigned char *buffer, const unsigned int size)
{
	//reconnect();
	int err;
	std::cout << "try and send\n";
	//err = client.write(buffer, size+ sizeof(MESSAGE_SEND_HEADER) + sizeof(MESSAGE_SEND_TRAILER));
	err = client.write(buffer, size);

	std::cout << "sent:"<<err << " of "<<size<<"\n";
	if (err < size){
		reconnect();
		err = client.write(buffer, size);
		std::cout << "resent:"<<err <<"\n";
	}
	return err;
}

int tuyaLocal::receive(unsigned char *buffer, const unsigned int maxsize, const unsigned int minsize)
{
	int index = 0;
	int prefix_index = 0;
	int trailer_index = 4;
	int tries = 0;
	int total=0;
	std::cout << "recieve\n";
	//send_heartbeat();
	while (trailer_index<8 && tries++ < 100)
	{
		if (!client.connected()){
			std::cout << "client not connected\n";
			break;
		}
		int numbytes = client.available();
		if (numbytes >0 )std::cout << "available:"<< numbytes<<"\n";
		for (auto i = 0; i < numbytes; i++)
		{
			total++;
			char c = client.read();
			//std::cout << c << "\n";
			if (trailer_index < 8 && c == MESSAGE_SEND_TRAILER[trailer_index] ){
				trailer_index++;
				//std::cout << "t" << trailer_index<<"\n";
			}else if(trailer_index < 8){
				trailer_index=4;
			}
			if (prefix_index < 4 && c != MESSAGE_SEND_HEADER[prefix_index])
			{
				index = 0;
				prefix_index = 0;
				//std::cout << "x";
			}
			else
			{
				//std::cout << "v" << (prefix_index+1)<<"\n";
				buffer[index] = c;
				index++;
				if (prefix_index < 4){
					prefix_index++;
				}
			}
			
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	std::cout << "read:"<< total << " recieved: "<< index << "\n";
	return (int)index;
}

void tuyaLocal::disconnect()
{
	client.stop();
}

bool tuyaLocal::reconnect()
{
	return ConnectToDevice(m_hostname, m_portnumber, m_retries);
}
