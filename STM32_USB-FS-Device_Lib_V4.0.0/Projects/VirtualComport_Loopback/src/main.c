/**
  ******************************************************************************
  * @file    main.c
  * @author  MCD Application Team
  * @version V4.0.0
  * @date    21-January-2013
  * @brief   Virtual Com Port Demo main file
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2013 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software 
  * distributed under the License is distributed on an "AS IS" BASIS, 
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */


/**
  ******************************************************************************
  * @file    HASH/HMAC_SHA1/main.c
  * @author  MCD Application Team
  * @version V2.0.6
  * @date    25-June-2013
  * @brief   Main program body
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2013 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */


#include <stdio.h>
#include "crypto.h"     
#include "hw_config.h"
#include "usb_lib.h"
#include "usb_desc.h"
#include "usb_pwr.h"

GPIO_InitTypeDef        GPIO_InitStructure;

typedef enum {FAILED = 0, PASSED = !FAILED} TestStatus;

#define Expected_OutputMessage_LENGTH 32


volatile uint8_t InputMessage[80];
volatile uint8_t checksum;

volatile uint32_t minimum_nonce = 0;
volatile uint32_t maximum_nonce = 0xffffffff;
volatile uint32_t maximum_hash;
volatile uint8_t expected_hash[32];
volatile uint8_t blockheader_quickrequest[80];
volatile uint8_t blockheader_miningcore[80];
volatile uint8_t share_buffer[256][4]; /*256 shares can be held in the buffer, only the Nonce is stored as the rest of the blockheader is shared between them.
										If the host changes the Blockheader all remaining shares are deleted.*/
volatile uint8_t share_buffer_writeaddress = 0; //addresses are 8 bit so that wrapping around doesn`t need to be handled in code
volatile uint8_t share_buffer_readaddress = 0;
	

uint8_t HMAC_Key[] =
  {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f
  };

#define HMAC_KeyLength 64;

#define HMAC_LENGTH 32

volatile uint8_t type_of_work; //0 = no work 1 = check if hash ok 2 = return hash 3 = find nonce with hash smaller than given value aka search for block/share


uint32_t InputLength = 80;
uint8_t MessageDigest[CRL_SHA256_SIZE];
int32_t MessageDigestLength = 0;


volatile uint8_t output_data_buffer[120];
volatile uint8_t input_data_buffer[120];

volatile uint8_t input_data_buffer_length = 0;




int32_t Compute_Hash(uint8_t* InputMessage,
                                  uint32_t InputMessageLength,
                                  uint8_t *MessageDigest,
                                  int32_t* MessageDigestLength);

uint8_t compare_buffers(const uint8_t* pBuffer,
                     uint8_t* pBuffer1,
                     uint16_t BufferLength);



extern __IO uint8_t Receive_Buffer[128];
extern __IO  uint32_t Receive_length ;
extern __IO  uint32_t length ;
uint8_t Send_Buffer[64];
uint32_t packet_sent=1;
uint32_t packet_receive=1;


uint8_t get_data_from_host(void)
{
  CDC_Receive_DATA();
if(Receive_length != 0)  
{
  //flush input buffer
  for(uint8_t i = 0; i < 120; i ++)
  {
    input_data_buffer[i] = 0;
  }
  
  if(Receive_Buffer[0] == 0)
  {
    type_of_work = 0; //setting type_of_work to zero will stop the running task on next check and disable restart. 0x00 can be used to stop worker or to bring CPU back to defined state.
  }
  if(Receive_Buffer[0] != 0)
  {
    uint8_t already_copied_length = 0;
    input_data_buffer_length = Receive_Buffer[0] - 1;
    while(input_data_buffer_length > already_copied_length + 2)
    {
      CDC_Receive_DATA();
      uint8_t i = 0;
      while(i < Receive_length)
      {
        input_data_buffer[already_copied_length + i] = Receive_Buffer[i];
        i ++;
      }
      already_copied_length = already_copied_length + Receive_length;
      Receive_length = 0;
    }
    checksum = input_data_buffer[input_data_buffer_length];
  }
  Receive_length = 0;
  //check data with checksum
  uint64_t checksum_midstate = 0;
  for(uint8_t i = 0; i < input_data_buffer_length; i ++)
  {
    checksum_midstate = checksum_midstate + input_data_buffer[i] * i;
  }
  if(checksum_midstate % 128 + 42 == checksum)
  {
    for(uint8_t i = 1; i < input_data_buffer_length; i ++)
    {
      input_data_buffer[i - 1] = input_data_buffer[i];
    }
    input_data_buffer_length --; 
    CDC_Send_DATA ("a",1); 
    for(volatile int delay = 0; delay < 50000; delay ++);
    return 1;
  }
  CDC_Send_DATA ("n",1);
}
  return 0;
}

void send_output_data_buffer(void)
{
  if(output_data_buffer != 0)
  {
  //compute and add checksum
  uint8_t output_data_buffer_length = output_data_buffer[0];
  uint64_t checksum_midstate = 0;
  for(uint8_t i = 1; i < output_data_buffer_length - 1; i ++)
  {
    checksum_midstate = checksum_midstate + output_data_buffer[i] * i;
  }
  output_data_buffer[output_data_buffer_length - 1] = checksum_midstate % 128 + 42;
  //send data out via USB
  CDC_Send_DATA ((unsigned char*)(output_data_buffer), output_data_buffer_length);
  while(packet_sent  != 1);
  } 
}

void delay_ms(uint32_t ms)
{
	while(ms > 0)
	{
		ms --;
		for(volatile int delay = 0; delay < 72000; delay ++);
	}	
}
uint8_t do_work(void)
{
  switch(type_of_work) 
  {
  case 0: return 0; break;
  case 1:
  Compute_Hash((uint8_t*)blockheader_quickrequest,80,(uint8_t*)MessageDigest,&MessageDigestLength);
  if(compare_buffers(MessageDigest,(uint8_t*)expected_hash,32))
  {
    output_data_buffer[0] = 4; //length
    output_data_buffer[1] = 0x23;  //hash matches blockheader (aka. data)
    output_data_buffer[2] = 0xf8;  //data2
    type_of_work = 0;
    return 1;
  }
  else
  {
    output_data_buffer[0] = 4; //length
    output_data_buffer[1] = 0x5e;  //hash doesn`t match blockheader (aka. data)
    output_data_buffer[2] = 0x07;  //data2
    type_of_work = 0;
    return 1;
  }
  break;
  case 2:
  if(!Compute_Hash((uint8_t*)blockheader_quickrequest,80,MessageDigest,&MessageDigestLength))  
  {
    output_data_buffer[0] = 34;
    for(uint8_t i = 0; i < 32; i ++)
    {
      output_data_buffer[i + 1] = MessageDigest[i];
    }
    type_of_work = 0;
    return 1;
  }
  break;
  case 3:
  //get shares from buffer
  if(share_buffer_writeaddress == share_buffer_readaddress)
  {
      output_data_buffer[0] = 4; //length
      output_data_buffer[1] = 0x55;  //no shares available
      output_data_buffer[2] = 0x66;  //data2
  }
  else
  {
    output_data_buffer[0] = 7; //length
    output_data_buffer[1] = 0x88;  //transmitting Nonce
    output_data_buffer[2] = share_buffer[share_buffer_readaddress][0];  //Nonce
	output_data_buffer[3] = share_buffer[share_buffer_readaddress][1];
	output_data_buffer[4] = share_buffer[share_buffer_readaddress][2];
	output_data_buffer[5] = share_buffer[share_buffer_readaddress][3];
	
  	share_buffer_readaddress ++;
  }
  delay_ms(10);
  return 1;
  break;
 
  case 4: 
    output_data_buffer[0] = 0x1e; //length
   output_data_buffer[1] = 0x48;
   output_data_buffer[2] = 0x57;
   output_data_buffer[3] = 0x3a;
   output_data_buffer[4] = 0x20;
   output_data_buffer[5] = 0x56;
   output_data_buffer[6] = 0x31;
   output_data_buffer[7] = 0x2e;
   output_data_buffer[8] = 0x30;
   output_data_buffer[9] = 0x0d;
   output_data_buffer[10] = 0x0a;
   output_data_buffer[11] = 0x53;
   output_data_buffer[12] = 0x57;
   output_data_buffer[13] = 0x3a;
   output_data_buffer[14] = 0x20;
   output_data_buffer[15] = 0x56;
   output_data_buffer[16] = 0x31;
   output_data_buffer[17] = 0x2e;
   output_data_buffer[18] = 0x30;
   output_data_buffer[19] = 0x0d;
   output_data_buffer[20] = 0x0a;
   output_data_buffer[21] = 0x43;
   output_data_buffer[22] = 0x53;
   output_data_buffer[23] = 0x3a;
   output_data_buffer[24] = 0x20;
   output_data_buffer[25] = 0x56;
   output_data_buffer[26] = 0x31;
   output_data_buffer[27] = 0x2e;
   output_data_buffer[28] = 0x30;
   return 1; break;
  default: return 0; break;
  }
  return 0;
}

uint8_t load_work(void)
{
  switch(input_data_buffer[0])
  {
  case 1: type_of_work = 4;
   
  return 1; break;
  case 2: type_of_work = 1;
  for(uint8_t i = 0; i < 80; i ++)
  {
    blockheader_quickrequest[i] = input_data_buffer[i + 1];
  }
  for(uint8_t i = 0; i < 32; i ++)
  {
    expected_hash[i] = input_data_buffer[i + 81];
  }
  return 1; break;
  case 3: type_of_work = 2;
  for(uint8_t i = 0; i < 80; i ++)
  {
    blockheader_quickrequest[i] = input_data_buffer[i + 1];
  }
  return 1; break;
  case 4:
  for(uint8_t i = 0; i < 76; i ++)
  {
    blockheader_miningcore[i] = input_data_buffer[i + 1];
  }
  share_buffer_writeaddress = 0;
  share_buffer_readaddress = 0;
  return 0; break;
  case 5:
  maximum_hash = *((uint32_t*)(input_data_buffer + 1));
  share_buffer_writeaddress = 0;
  share_buffer_readaddress = 0;
  return 0; break;
  case 6:
  minimum_nonce = *((uint32_t*)(input_data_buffer + 1));
  maximum_nonce = *((uint32_t*)(input_data_buffer + 5));
  *((uint32_t*)(blockheader_miningcore + 75)) = minimum_nonce; 
  share_buffer_writeaddress = 0;
  share_buffer_readaddress = 0;
  return 0; break;
  case 7:
  type_of_work = 3;
  return 1;
  break;
  default:
  type_of_work = 0;
  break;
  }
  return 0;
}



    int main(void)
{
  
  Set_System();
  Set_USBClock();
  USB_Interrupts_Config();
  USB_Init();
  

    /*!< At this stage the microcontroller clock setting is already configured, 
       this is done through SystemInit() function which is called from startup
       file (startup_stm32f30x.s) before to branch to application main.
       To reconfigure the default setting of SystemInit() function, refer to
       system_stm32f30x.c file
     */

  *((uint32_t*)(blockheader_miningcore + 75)) = 0;  //set Nonce to 0
   
  
  while         (1)
  {
    if (bDeviceState == CONFIGURED)
    {
		/*
		This while(1) loop contains the miningcore. It searches for blocks if the miner has nothing else to do, without the host 
		having to ask it to do so.
		A found share goes into the ringbuffer, and if the host doesn`t  request it the share will be overwritten. 
		*/
      while(1)
      { 
		  while(*((uint32_t*)(blockheader_miningcore + 76)) < maximum_nonce)
		  {	
			  if(get_data_from_host())
				{
			  	  if(load_work())
			  	  {
			  		  if(do_work())
			  		  {
			  			  send_output_data_buffer();
			  		  }
			  	  }
				}  
				
		    if(!Compute_Hash((uint8_t*)blockheader_miningcore,80,MessageDigest,&MessageDigestLength))  
		    {
			if(MessageDigest[31] == 0) //if the MSByte is 0 we check, if the Hash matches difficulty. This happens about 6 times a second
			{
				uint32_t hash_MSBs = (MessageDigest[31] << 24) + (MessageDigest[30] << 16) + (MessageDigest[29] << 8) + MessageDigest[28];
  		      if(hash_MSBs <= maximum_hash)
  		      {
  				  //Share found, append to ringbuffer
  				  share_buffer[share_buffer_writeaddress][0] = blockheader_miningcore[76];
  				  share_buffer[share_buffer_writeaddress][1] = blockheader_miningcore[77];
  				  share_buffer[share_buffer_writeaddress][2] = blockheader_miningcore[78];
  				  share_buffer[share_buffer_writeaddress][3] = blockheader_miningcore[79];
				 
  				  share_buffer_writeaddress ++;  
  		      }
			}
		    }
		    *((uint32_t*)(blockheader_miningcore + 76)) =  *((uint32_t*)(blockheader_miningcore + 76)) + 1;
		  }
		  output_data_buffer[0] = 4; //length
		  output_data_buffer[1] = 0x00;  //maximum nonce reached. there might have been valid shares before. (aka. data)
		  output_data_buffer[2] = 0x00;
       	  send_output_data_buffer();
      }  

	  
	  
    }
  }
} 




/**




  * @brief  SHA256 HASH digest compute example.
  * @param  InputMessage: pointer to input message to be hashed.
  * @param  InputMessageLength: input data message length in byte.
  * @param  MessageDigest: pointer to output parameter that will handle message digest
  * @param  MessageDigestLength: pointer to output digest length.
  * @retval error status: can be HASH_SUCCESS if success or one of
  *         HASH_ERR_BAD_PARAMETER, HASH_ERR_BAD_CONTEXT,
  *         HASH_ERR_BAD_OPERATION if error occured.
  */
int32_t Compute_Hash(uint8_t* InputMessage, uint32_t InputMessageLength, uint8_t *MessageDigest, int32_t* MessageDigestLength)
{
  Crypto_DeInit();
  
  HMAC_SHA256ctx_stt HMAC_SHA256ctx;
  uint32_t error_status = HASH_SUCCESS;

  /* Set the size of the desired MAC*/
  HMAC_SHA256ctx.mTagSize = CRL_SHA256_SIZE;

  /* Set flag field to default value */
  HMAC_SHA256ctx.mFlags = E_HASH_DEFAULT;

  /* Set the key pointer in the context*/
  HMAC_SHA256ctx.pmKey = HMAC_Key;

  /* Set the size of the key */
  HMAC_SHA256ctx.mKeySize = HMAC_KeyLength;

  /* Initialize the context */
  error_status = HMAC_SHA256_Init(&HMAC_SHA256ctx);

  /* check for initialization errors */
  if (error_status == HASH_SUCCESS)
  {
    /* Add data to be hashed */
    error_status = HMAC_SHA256_Append(&HMAC_SHA256ctx,
                                    InputMessage,
                                    InputMessageLength);

    if (error_status == HASH_SUCCESS)
    {
      /* retrieve */
      error_status = HMAC_SHA256_Finish(&HMAC_SHA256ctx, MessageDigest, MessageDigestLength);
    }
  }

  return error_status;
}



 

  
uint8_t compare_buffers(const uint8_t* pBuffer, uint8_t* pBuffer1, uint16_t BufferLength)
{
  while (BufferLength--)
  {
    if (*pBuffer != *pBuffer1)
    {
      return 0;
    }

    pBuffer++;
    pBuffer1++;
  }

  return 1;
}

#ifdef  USE_FULL_ASSERT


void assert_failed(uint8_t* file, uint32_t line)
{
  while (1)
  {}
}
#endif

/**
  * @}
  */


#ifdef USE_FULL_ASSERT
/*******************************************************************************
* Function Name  : assert_failed
* Description    : Reports the name of the source file and the source line number
*                  where the assert_param error has occurred.
* Input          : - file: pointer to the source file name
*                  - line: assert_param error line source number
* Output         : None
* Return         : None
*******************************************************************************/
void assert_failed(uint8_t* file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {}
}
#endif




/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
