#include "main.h"
#include "security.h"
#include "security_protocol.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Private variables ---------------------------------------------------------*/

UART_HandleTypeDef huart1;

/* Private function prototypes ---------------------------------------------*/

void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART1_UART_Init(void);


/* USER CODE BEGIN PV */

#define RX_BUFFER_SIZE 256

static char rxBuffer[RX_BUFFER_SIZE];

static uint8_t expectedHMAC[HMAC_SHA256_SIZE];

static SecurityDecision decision;

static char response[256];

static uint32_t receivedPackets = 0;

/* USER CODE END PV */


/* USER CODE BEGIN 0 */

/* ============================================================
 * Receive one complete line from USART1
 * ============================================================ */

static uint8_t ReceiveLine(char *buffer, uint16_t bufferSize)
{
    uint8_t byte;
    uint16_t index = 0;

    while (index < bufferSize - 1)
    {
        if (HAL_UART_Receive(
                &huart1,
                &byte,
                1,
                1000) != HAL_OK)
        {
            return 0;
        }

        if (byte == '\n')
        {
            buffer[index] = '\0';
            return 1;
        }

        if (byte != '\r')
        {
            buffer[index++] = (char)byte;
        }
    }

    buffer[bufferSize - 1] = '\0';

    return 1;
}


/* ============================================================
 * Convert hexadecimal character to numeric value
 * ============================================================ */

static uint8_t HexCharToValue(char c)
{
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');

    if (c >= 'A' && c <= 'F')
        return (uint8_t)(c - 'A' + 10);

    if (c >= 'a' && c <= 'f')
        return (uint8_t)(c - 'a' + 10);

    return 0;
}


/* ============================================================
 * Convert 64 hexadecimal characters into 32-byte HMAC
 * ============================================================ */

static uint8_t ParseHMAC(const char *hex, uint8_t *output)
{
    if (strlen(hex) != 64)
    {
        return 0;
    }

    for (uint8_t i = 0; i < 32; i++)
    {
        output[i] =
            (HexCharToValue(hex[i * 2]) << 4) |
             HexCharToValue(hex[i * 2 + 1]);
    }

    return 1;
}


/* ============================================================
 * Process one complete VERIFY frame
 *
 * Format:
 *
 * VERIFY|PACKET|HMAC
 *
 * Example:
 *
 * VERIFY|PKT,1.0,MAIN_01,...,GAS=1234,...|AABBCC...
 *
 * ============================================================ */

static void ProcessVerifyFrame(char *frame)
{
    char *firstSeparator;
    char *secondSeparator;

    char *packet;
    char *hmacString;

    uint8_t calculatedHMAC[HMAC_SHA256_SIZE];

    uint8_t hmacMatch = 0;


    /* --------------------------------------------------------
     * Check VERIFY prefix
     * -------------------------------------------------------- */

    if (strncmp(frame, "VERIFY|", 7) != 0)
    {
        return;
    }


    /* --------------------------------------------------------
     * Find first separator
     *
     * VERIFY|PACKET|HMAC
     *        ^
     * -------------------------------------------------------- */

    firstSeparator = strchr(frame, '|');

    if (firstSeparator == NULL)
    {
        return;
    }


    /* --------------------------------------------------------
     * Find final separator
     *
     * VERIFY|PACKET|HMAC
     *               ^
     * -------------------------------------------------------- */

    secondSeparator = strrchr(
        firstSeparator + 1,
        '|'
    );

    if (secondSeparator == NULL)
    {
        return;
    }


    /* --------------------------------------------------------
     * Separate packet and HMAC
     * -------------------------------------------------------- */

    *firstSeparator = '\0';
    *secondSeparator = '\0';

    packet = firstSeparator + 1;
    hmacString = secondSeparator + 1;

    char packetId[16] = {0};

    char *p = packet;

    /* Skip:
     * PKT
     * 1.0
     * MAIN_01
     *
     * and extract packet number
     */
    int fields = sscanf(
        p,
        "PKT,1.0,MAIN_01,%15[^,]",
        packetId
    );

    /* --------------------------------------------------------
     * Validate packet length
     * -------------------------------------------------------- */

    if (strlen(packet) >= MAX_PACKET_SIZE)
    {
        return;
    }


    /* --------------------------------------------------------
     * Parse received HMAC
     * -------------------------------------------------------- */

    if (!ParseHMAC(
            hmacString,
            expectedHMAC))
    {
        return;
    }


    /* ========================================================
     * CALCULATE HMAC ON BLUE PILL
     * ======================================================== */

    HMAC_SHA256(
        (const uint8_t *)SECURITY_KEY,
        strlen(SECURITY_KEY),

        (const uint8_t *)packet,
        strlen(packet),

        calculatedHMAC
    );


    /* ========================================================
     * CONSTANT-TIME STYLE COMPARISON
     * ======================================================== */

    uint8_t difference = 0;

    for (uint8_t i = 0; i < HMAC_SHA256_SIZE; i++)
    {
        difference |=
            calculatedHMAC[i] ^ expectedHMAC[i];
    }


    hmacMatch = (difference == 0U) ? 1U : 0U;


    /* ========================================================
     * SECURITY DECISION
     * ======================================================== */

    if (hmacMatch)
    {
        decision.authenticated = 1;

        /*
         * Authenticated packets are evaluated for
         * the requested security test condition.
         *
         * The Blue Pill makes the actual
         * threat → policy decision.
         */
        decision.threat =
            Threat_FromPacket((const uint8_t *)packet);

        decision.policy =
            Policy_FromThreat(decision.threat);
    }
    else
    {
        /*
         * HMAC failure always overrides everything
         * and immediately becomes CRITICAL.
         */
        decision.authenticated = 0;
        decision.threat = THREAT_CRITICAL;
        decision.policy = POLICY_PARANOID;
    }


    /* --------------------------------------------------------
     * Increment packet counter
     * -------------------------------------------------------- */

    receivedPackets++;


    /* --------------------------------------------------------
     * Create ONLY the protocol response
     *
     * IMPORTANT:
     * No debug messages are transmitted here.
     * -------------------------------------------------------- */

    snprintf(
        response,
        sizeof(response),

        "SECURITY,PKT=%s,%s,%s,%s\r\n",

        packetId,

        decision.authenticated
            ? "VALID"
            : "INVALID",

        Threat_ToString(
            decision.threat),

        Policy_ToString(
            decision.policy)
    );


    /* --------------------------------------------------------
     * Send security response
     * -------------------------------------------------------- */

    HAL_UART_Transmit(
        &huart1,

        (uint8_t *)response,

        strlen(response),

        HAL_MAX_DELAY
    );


    /* --------------------------------------------------------
     * LED indication
     *
     * PC13 is active-low.
     * -------------------------------------------------------- */

    if (decision.authenticated)
    {
        HAL_GPIO_WritePin(
            GPIOC,
            GPIO_PIN_13,
            GPIO_PIN_RESET
        );
    }
    else
    {
        HAL_GPIO_WritePin(
            GPIOC,
            GPIO_PIN_13,
            GPIO_PIN_SET
        );
    }
}
/* USER CODE END 0 */


/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
    /* MCU Configuration --------------------------------------*/

    HAL_Init();

    SystemClock_Config();

    MX_GPIO_Init();

    MX_USART1_UART_Init();


    /* USER CODE BEGIN 2 */

    const char startupMessage[] =
        "\r\n"
        "================================================\r\n"
        "       BLUE PILL SECURITY COPROCESSOR\r\n"
        "              PHASE 3 START\r\n"
        "================================================\r\n"
        "[SECURITY] SHA-256       : READY\r\n"
        "[SECURITY] HMAC-SHA256   : READY\r\n"
        "[SECURITY] AUTHENTICATION: READY\r\n"
        "[SECURITY] UART          : READY\r\n"
        "[SECURITY] ATOMIC FRAME  : READY\r\n"
        "================================================\r\n\r\n";


    HAL_UART_Transmit(
        &huart1,
        (uint8_t *)startupMessage,
        strlen(startupMessage),
        HAL_MAX_DELAY
    );


    /* USER CODE END 2 */


    /* Infinite loop ------------------------------------------*/

    while (1)
    {
        /*
         * Wait for one complete:
         *
         * VERIFY|PACKET|HMAC
         */

        if (ReceiveLine(
                rxBuffer,
                sizeof(rxBuffer)))
        {
            ProcessVerifyFrame(rxBuffer);
        }
    }
}


/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    RCC_OscInitStruct.OscillatorType =
        RCC_OSCILLATORTYPE_HSE;

    RCC_OscInitStruct.HSEState =
        RCC_HSE_ON;

    RCC_OscInitStruct.HSEPredivValue =
        RCC_HSE_PREDIV_DIV1;

    RCC_OscInitStruct.HSIState =
        RCC_HSI_ON;

    RCC_OscInitStruct.PLL.PLLState =
        RCC_PLL_ON;

    RCC_OscInitStruct.PLL.PLLSource =
        RCC_PLLSOURCE_HSE;

    RCC_OscInitStruct.PLL.PLLMUL =
        RCC_PLL_MUL9;

    if (HAL_RCC_OscConfig(
            &RCC_OscInitStruct) != HAL_OK)
    {
        Error_Handler();
    }


    RCC_ClkInitStruct.ClockType =
        RCC_CLOCKTYPE_HCLK |
        RCC_CLOCKTYPE_SYSCLK |
        RCC_CLOCKTYPE_PCLK1 |
        RCC_CLOCKTYPE_PCLK2;

    RCC_ClkInitStruct.SYSCLKSource =
        RCC_SYSCLKSOURCE_PLLCLK;

    RCC_ClkInitStruct.AHBCLKDivider =
        RCC_SYSCLK_DIV1;

    RCC_ClkInitStruct.APB1CLKDivider =
        RCC_HCLK_DIV2;

    RCC_ClkInitStruct.APB2CLKDivider =
        RCC_HCLK_DIV1;


    if (HAL_RCC_ClockConfig(
            &RCC_ClkInitStruct,
            FLASH_LATENCY_2) != HAL_OK)
    {
        Error_Handler();
    }
}


/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{
    huart1.Instance =
        USART1;

    huart1.Init.BaudRate =
        115200;

    huart1.Init.WordLength =
        UART_WORDLENGTH_8B;

    huart1.Init.StopBits =
        UART_STOPBITS_1;

    huart1.Init.Parity =
        UART_PARITY_NONE;

    huart1.Init.Mode =
        UART_MODE_TX_RX;

    huart1.Init.HwFlowCtl =
        UART_HWCONTROL_NONE;

    huart1.Init.OverSampling =
        UART_OVERSAMPLING_16;


    if (HAL_UART_Init(&huart1) != HAL_OK)
    {
        Error_Handler();
    }
}


/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
    GPIO_InitTypeDef GPIO_InitStruct = {0};


    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOD_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();


    /*
     * Blue Pill onboard LED:
     * PC13
     */

    HAL_GPIO_WritePin(
        GPIOC,
        GPIO_PIN_13,
        GPIO_PIN_SET
    );


    GPIO_InitStruct.Pin =
        GPIO_PIN_13;

    GPIO_InitStruct.Mode =
        GPIO_MODE_OUTPUT_PP;

    GPIO_InitStruct.Pull =
        GPIO_NOPULL;

    GPIO_InitStruct.Speed =
        GPIO_SPEED_FREQ_LOW;


    HAL_GPIO_Init(
        GPIOC,
        &GPIO_InitStruct
    );
}


/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
    __disable_irq();

    while (1)
    {
        HAL_GPIO_TogglePin(
            GPIOC,
            GPIO_PIN_13
        );

        HAL_Delay(250);
    }
}


#ifdef USE_FULL_ASSERT

void assert_failed(
    uint8_t *file,
    uint32_t line)
{
    /* User can add implementation here */
}

#endif
