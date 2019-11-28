/*
 * Copyright 2008-2015 Arsen Chaloyan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * Mandatory rules concerning plugin implementation.
 * 1. Each plugin MUST implement a plugin/engine creator function
 *    with the exact signature and name (the main entry point)
 *        MRCP_PLUGIN_DECLARE(mrcp_engine_t*) mrcp_plugin_create(apr_pool_t *pool)
 * 2. Each plugin MUST declare its version number
 *        MRCP_PLUGIN_VERSION_DECLARE
 * 3. One and only one response MUST be sent back to the received request.
 * 4. Methods (callbacks) of the MRCP engine channel MUST not block.
 *   (asynchronous response can be sent from the context of other thread)
 * 5. Methods (callbacks) of the MPF engine stream MUST not block.
 */

#include "mrcp_recog_engine.h"
#include "apt_consumer_task.h"
#include "apt_log.h"
#include "apr_file_info.h"
#include "pfmsc/asr.h"
#include "pfsdk/dlp.h"

#define RECOG_ENGINE_TASK_NAME "UASR Recog Engine"
#define RECOG_ENGINE_CONF_FILE_NAME "uasrrecog.xml"

static uint32_t	g_dftTimeoutNoInput = 45;
static uint32_t	g_dftTimeoutDetecting = 30;
static PFMSC::SysParams	g_dftParamsSys;
static PFMSC::VendorParams	g_dftParamsVendor;
static PFMSC::ASRParams	g_dftParamsASR;
static apt_bool_t uasr_recog_load_cfg_items(const char *file_path_conf, const char *dir_path_log);

typedef struct uasr_recog_engine_t uasr_recog_engine_t;
typedef struct uasr_recog_channel_t uasr_recog_channel_t;
typedef struct uasr_recog_msg_t uasr_recog_msg_t;

/** Declaration of recognizer engine methods */
static apt_bool_t uasr_recog_engine_destroy(mrcp_engine_t *engine);
static apt_bool_t uasr_recog_engine_open(mrcp_engine_t *engine);
static apt_bool_t uasr_recog_engine_close(mrcp_engine_t *engine);
static mrcp_engine_channel_t* uasr_recog_engine_channel_create(mrcp_engine_t *engine, apr_pool_t *pool);

static const struct mrcp_engine_method_vtable_t engine_vtable = {
	uasr_recog_engine_destroy,
	uasr_recog_engine_open,
	uasr_recog_engine_close,
	uasr_recog_engine_channel_create
};


/** Declaration of recognizer channel methods */
static apt_bool_t uasr_recog_channel_destroy(mrcp_engine_channel_t *channel);
static apt_bool_t uasr_recog_channel_open(mrcp_engine_channel_t *channel);
static apt_bool_t uasr_recog_channel_close(mrcp_engine_channel_t *channel);
static apt_bool_t uasr_recog_channel_request_process(mrcp_engine_channel_t *channel, mrcp_message_t *request);

static const struct mrcp_engine_channel_method_vtable_t channel_vtable = {
	uasr_recog_channel_destroy,
	uasr_recog_channel_open,
	uasr_recog_channel_close,
	uasr_recog_channel_request_process
};

/** Declaration of recognizer audio stream methods */
static apt_bool_t uasr_recog_stream_destroy(mpf_audio_stream_t *stream);
static apt_bool_t uasr_recog_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec);
static apt_bool_t uasr_recog_stream_close(mpf_audio_stream_t *stream);
static apt_bool_t uasr_recog_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame);

static const mpf_audio_stream_vtable_t audio_stream_vtable = {
	uasr_recog_stream_destroy,
	NULL,
	NULL,
	NULL,
	uasr_recog_stream_open,
	uasr_recog_stream_close,
	uasr_recog_stream_write,
	NULL
};

/*
#define PFMSC_ASR_STATUS_INVALID	0
#define PFMSC_ASR_STATUS_FEEDING	1	// feeding audio data to server
#define PFMSC_ASR_STATUS_LOOKING	2	// server begin handling audio data
#define PFMSC_ASR_STATUS_DETECTING	3	// first sample detected
#define PFMSC_ASR_STATUS_DETECTED	4	// last sample detected
*/
struct uasr_recog_state_machine_t {
	uint64_t	lluTimeBeginSession;
	uint64_t	lluTimeBeginSpeaking;
	uint64_t	lluTimeSpeechDetected;

	uint32_t	uAsrStatusPrev;

	PFThreadMutex	mutexAsrStatus;
	uint32_t	uAsrStatus;
	std::string	strAsrResult;

	uint32_t	uTimeoutNoInput;
	uint32_t	uTimeoutDetecting;

	uasr_recog_state_machine_t(uint64_t lluTimeBeginSessionParam, uint32_t uTimeoutNoInputParam, uint32_t uTimeoutDetecting)
		:lluTimeBeginSession(lluTimeBeginSessionParam), lluTimeBeginSpeaking(0), lluTimeSpeechDetected(0)
		, uAsrStatusPrev(PFMSC_ASR_STATUS_FEEDING)
		, uAsrStatus(PFMSC_ASR_STATUS_FEEDING)
		, uTimeoutNoInput(uTimeoutNoInputParam), uTimeoutDetecting(uTimeoutDetecting)
	{}
};

enum uasr_recog_event_et {
	uasr_recog_event_e_Ignore			=	0,
	uasr_recog_event_e_BeginSpeaking	=	1,
	uasr_recog_event_e_SpeechDetected	=	2,
	uasr_recog_event_e_TimeoutNoInput	=	3,
	uasr_recog_event_e_TimeoutDetecting	=	4,
	uasr_recog_event_e_Error			=	5,
};

static int32_t				uasr_recog_sm_on_notify(void* pvContext, uint32_t uAsrStatus, const char* pstrAsrResult);
static uasr_recog_event_et	uasr_recog_sm_get_status(uasr_recog_state_machine_t* recog_sm);

/** Declaration of uasr recognizer engine */
struct uasr_recog_engine_t {
	apt_consumer_task_t    *task;
};

/** Declaration of uasr recognizer channel */
struct uasr_recog_channel_t {
	/** Back pointer to engine */
	uasr_recog_engine_t     *uasr_engine;
	/** Engine channel base */
	mrcp_engine_channel_t   *channel;

	/** Active (in-progress) recognition request */
	mrcp_message_t          *recog_request;
	/** Pending stop response */
	mrcp_message_t          *stop_response;
	/** Indicates whether input timers are started */
	apt_bool_t               timers_started;

	PFMSC::ASRSession		*asr_session;
	uasr_recog_state_machine_t	*recog_sm;
};

typedef enum {
	UASR_RECOG_MSG_OPEN_CHANNEL,
	UASR_RECOG_MSG_CLOSE_CHANNEL,
	UASR_RECOG_MSG_REQUEST_PROCESS
} uasr_recog_msg_type_e;

/** Declaration of uasr recognizer task message */
struct uasr_recog_msg_t {
	uasr_recog_msg_type_e  type;
	mrcp_engine_channel_t *channel; 
	mrcp_message_t        *request;
};

static apt_bool_t uasr_recog_msg_signal(uasr_recog_msg_type_e type, mrcp_engine_channel_t *channel, mrcp_message_t *request);
static apt_bool_t uasr_recog_msg_process(apt_task_t *task, apt_task_msg_t *msg);

/** Declare this macro to set plugin version */
MRCP_PLUGIN_VERSION_DECLARE

/**
 * Declare this macro to use log routine of the server, plugin is loaded from.
 * Enable/add the corresponding entry in logger.xml to set a cutsom log source priority.
 *    <source name="RECOG-PLUGIN" priority="DEBUG" masking="NONE"/>
 */
MRCP_PLUGIN_LOG_SOURCE_IMPLEMENT(RECOG_PLUGIN,"RECOG-PLUGIN")

/** Use custom log source mark */
#define RECOG_LOG_MARK   APT_LOG_MARK_DECLARE(RECOG_PLUGIN)

/** Create uasr recognizer engine */
MRCP_PLUGIN_DECLARE(mrcp_engine_t*) mrcp_plugin_create(apr_pool_t *pool)
{
	uasr_recog_engine_t *uasr_engine = (uasr_recog_engine_t*)apr_palloc(pool,sizeof(uasr_recog_engine_t));
	apt_task_t *task;
	apt_task_vtable_t *vtable;
	apt_task_msg_pool_t *msg_pool;

	msg_pool = apt_task_msg_pool_create_dynamic(sizeof(uasr_recog_msg_t),pool);
	uasr_engine->task = apt_consumer_task_create(uasr_engine,msg_pool,pool);
	if(!uasr_engine->task) {
		return NULL;
	}
	task = apt_consumer_task_base_get(uasr_engine->task);
	apt_task_name_set(task,RECOG_ENGINE_TASK_NAME);
	vtable = apt_task_vtable_get(task);
	if(vtable) {
		vtable->process_msg = uasr_recog_msg_process;
	}

	/* create engine base */
	return mrcp_engine_create(
				MRCP_RECOGNIZER_RESOURCE,  /* MRCP resource identifier */
				uasr_engine,               /* object to associate */
				&engine_vtable,            /* virtual methods table of engine */
				pool);                     /* pool to allocate memory from */
}

static apt_bool_t uasr_recog_load_cfg_items(const char *file_path_conf, const char *dir_path_log)
{
	apt_bool_t	bRet = FALSE;

	for (int32_t iOnce = 0; iOnce < 1; ++iOnce)
	{
		PFDLP	dlp(PFDLP::E_DT_XML);
		if (dlp.ParseFile(file_path_conf) != PF::E_Errno_SUCCESS)
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_ERROR,
				"uasr_recog - uasr_recog_load_cfg_items() failed on open config file[\"%s\"]!!!",
				file_path_conf
			);

			bRet = FALSE;
			break;
		}
		PFDLP::PNode	pxmlNodeRoot = dlp.GetRootNode();

		g_dftParamsSys.strLogLevel = dlp.GetNodeValue(dlp.GetChildNode(pxmlNodeRoot, "LogLevel"));
		g_dftParamsSys.strLogDir = dir_path_log;
		g_dftParamsSys.bRecordSwitchOn = strcasecmp(dlp.GetNodeValue(dlp.GetChildNode(pxmlNodeRoot, "LogLevel")).c_str(), "on") == 0;
		g_dftParamsSys.strRecordDir = dir_path_log;

		g_dftParamsVendor.strVendor = dlp.GetNodeValue(dlp.GetChildNode(pxmlNodeRoot, "Vendor"));
		g_dftParamsVendor.strAuthInfo = dlp.GetNodeValue(dlp.GetChildNode(pxmlNodeRoot, "AuthInfo"));
		g_dftParamsVendor.strExtInfo = dlp.GetNodeValue(dlp.GetChildNode(pxmlNodeRoot, "ExtInfo"));
		if (g_dftParamsVendor.strVendor.empty() || g_dftParamsVendor.strAuthInfo.empty())
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_ERROR,
				"uasr_recog - uasr_recog_load_cfg_items() failed on empty Vendor or AuthInfo!!!",
				file_path_conf
			);

			bRet = FALSE;
			break;
		}

		g_dftParamsASR.nSampleRate = dlp.GetIntNodeValue(dlp.GetChildNode(pxmlNodeRoot, "SampleRate"));
		g_dftParamsASR.nVadEos = dlp.GetIntNodeValue(dlp.GetChildNode(pxmlNodeRoot, "VadEos"));
		g_dftParamsASR.strResultFormat = dlp.GetNodeValue(dlp.GetChildNode(pxmlNodeRoot, "ResultFormat"));
		g_dftParamsASR.bEnableDigitise = (dlp.GetIntNodeValue(dlp.GetChildNode(pxmlNodeRoot, "EnableDigitise")) != 0);
		if ((g_dftParamsASR.nSampleRate != PFMSC::SampleRate8k) && (g_dftParamsASR.nSampleRate != PFMSC::SampleRate16k))
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_WARNING,
				"uasr_recog - uasr_recog_load_cfg_items() only %d or %d sample rate supported, use default[%d] instead!!!",
				PFMSC::SampleRate8k, PFMSC::SampleRate16k, PFMSC::SampleRateDft
			);
			g_dftParamsASR.nSampleRate = PFMSC::SampleRateDft;
		}
		if ((g_dftParamsASR.nVadEos < PFMSC::VadEosMin) || (g_dftParamsASR.nVadEos > PFMSC::VadEosMax))
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_WARNING,
				"uasr_recog - uasr_recog_load_cfg_items() only support VadEos between %d and %d, use default[%d] instead!!!",
				PFMSC::VadEosMin, PFMSC::VadEosMax, PFMSC::VadEosDft
			);
			g_dftParamsASR.nVadEos = PFMSC::VadEosDft;
		}

		bRet = TRUE;
	}

	return bRet;
}

/** Destroy recognizer engine */
static apt_bool_t uasr_recog_engine_destroy(mrcp_engine_t *engine)
{
	uasr_recog_engine_t *uasr_engine = (uasr_recog_engine_t*)engine->obj;
	if(uasr_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(uasr_engine->task);
		apt_task_destroy(task);
		uasr_engine->task = NULL;
	}
	return TRUE;
}

/** Open recognizer engine */
static apt_bool_t uasr_recog_engine_open(mrcp_engine_t *engine)
{
	uasr_recog_engine_t *uasr_engine = (uasr_recog_engine_t*)engine->obj;

	const char *file_path_conf = apt_confdir_filepath_get(engine->dir_layout, RECOG_ENGINE_CONF_FILE_NAME, engine->pool);
	const char *dir_path_log = apt_dir_layout_path_get(engine->dir_layout, APT_LAYOUT_LOG_DIR);

	if (!uasr_recog_load_cfg_items(file_path_conf, dir_path_log))
	{
		apt_log(RECOG_LOG_MARK, APT_PRIO_ERROR,
			"uasrrecog - uasr_recog_engine_open() failed on uasr_recog_load_cfg_items()!!!"
		);
		return FALSE;
	}

	if (PFMSC::ASRInit(&g_dftParamsSys, &g_dftParamsVendor) != PF::E_Errno_SUCCESS)
	{
		apt_log(RECOG_LOG_MARK, APT_PRIO_ERROR,
			"uasrrecog - uasr_recog_engine_open() failed PFMSC::ASRInit()!!!"
		);
		return FALSE;
	}

	apt_log(RECOG_LOG_MARK, APT_PRIO_INFO,
		"uasrrecog - uasr_recog_engine_open(%s) successfully.",
		file_path_conf
	);

	if(uasr_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(uasr_engine->task);
		apt_task_start(task);
	}
	return mrcp_engine_open_respond(engine,TRUE);
}

/** Close recognizer engine */
static apt_bool_t uasr_recog_engine_close(mrcp_engine_t *engine)
{
	uasr_recog_engine_t *uasr_engine = (uasr_recog_engine_t*)engine->obj;

	PFMSC::ASRFini();
	apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,
		"uasr_recog_engine_close() invoked."
		);

	if(uasr_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(uasr_engine->task);
		apt_task_terminate(task,TRUE);
	}
	return mrcp_engine_close_respond(engine);
}

static mrcp_engine_channel_t* uasr_recog_engine_channel_create(mrcp_engine_t *engine, apr_pool_t *pool)
{
	mpf_stream_capabilities_t *capabilities;
	mpf_termination_t *termination; 

	/* create uasr recog channel */
	uasr_recog_channel_t *recog_channel = (uasr_recog_channel_t*)apr_palloc(pool,sizeof(uasr_recog_channel_t));
	recog_channel->uasr_engine = (uasr_recog_engine_t*)engine->obj;
	recog_channel->recog_request = NULL;
	recog_channel->stop_response = NULL;
	recog_channel->asr_session = NULL;
	recog_channel->recog_sm = NULL;

	capabilities = mpf_sink_stream_capabilities_create(pool);
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000 | MPF_SAMPLE_RATE_16000,
			"LPCM");

	/* create media termination */
	termination = mrcp_engine_audio_termination_create(
			recog_channel,        /* object to associate */
			&audio_stream_vtable, /* virtual methods table of audio stream */
			capabilities,         /* stream capabilities */
			pool);                /* pool to allocate memory from */

	/* create engine channel base */
	recog_channel->channel = mrcp_engine_channel_create(
			engine,               /* engine */
			&channel_vtable,      /* virtual methods table of engine channel */
			recog_channel,        /* object to associate */
			termination,          /* associated media termination */
			pool);                /* pool to allocate memory from */

	apt_log(RECOG_LOG_MARK, APT_PRIO_INFO,
		"uasr_recog_engine_channel_create() invoked."
	);

	return recog_channel->channel;
}

/** Destroy engine channel */
static apt_bool_t uasr_recog_channel_destroy(mrcp_engine_channel_t *channel)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_INFO,
		"uasr_recog_channel_destroy() invoked."
	);

	/* nothing to destrtoy */
	return TRUE;
}

/** Open engine channel (asynchronous response MUST be sent)*/
static apt_bool_t uasr_recog_channel_open(mrcp_engine_channel_t *channel)
{
	return uasr_recog_msg_signal(UASR_RECOG_MSG_OPEN_CHANNEL,channel,NULL);
}

/** Close engine channel (asynchronous response MUST be sent)*/
static apt_bool_t uasr_recog_channel_close(mrcp_engine_channel_t *channel)
{
	return uasr_recog_msg_signal(UASR_RECOG_MSG_CLOSE_CHANNEL,channel,NULL);
}

/** Process MRCP channel request (asynchronous response MUST be sent)*/
static apt_bool_t uasr_recog_channel_request_process(mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	return uasr_recog_msg_signal(UASR_RECOG_MSG_REQUEST_PROCESS,channel,request);
}

/** Process RECOGNIZE request */
static apt_bool_t uasr_recog_channel_recognize(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	/* process RECOGNIZE request */
	mrcp_recog_header_t *recog_header;
	uasr_recog_channel_t *recog_channel = (uasr_recog_channel_t*)channel->method_obj;
	const mpf_codec_descriptor_t *descriptor = mrcp_engine_sink_stream_codec_get(channel);

	if(!descriptor) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Failed to Get Codec Descriptor " APT_SIDRES_FMT, MRCP_MESSAGE_SIDRES(request));
		response->start_line.status_code = MRCP_STATUS_CODE_METHOD_FAILED;
		return FALSE;
	}

	recog_channel->timers_started = TRUE;

	uint32_t	uTimeoutNoInput = g_dftTimeoutNoInput;
	uint32_t	uTimeoutDetecting = g_dftTimeoutDetecting;

	/* get recognizer header */
	recog_header = (mrcp_recog_header_t*)mrcp_resource_header_get(request);
	if(recog_header) {
		/*
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_START_INPUT_TIMERS) == TRUE) {
			recog_channel->timers_started = recog_header->start_input_timers;
		}
		*/
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_NO_INPUT_TIMEOUT) == TRUE) {
			uTimeoutNoInput = (uint32_t)recog_header->no_input_timeout;
		}
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT) == TRUE) {
			uTimeoutDetecting = (uint32_t)recog_header->speech_complete_timeout;
		}
	}

	int32_t	nRet = PF::E_Errno_ERR_GENERAL;
	for (int32_t iOnce = 0; iOnce < 1; ++iOnce)
	{
		recog_channel->recog_sm = new uasr_recog_state_machine_t(time(NULL), uTimeoutNoInput, uTimeoutDetecting);
		if (recog_channel->recog_sm == NULL)
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_WARNING,
				"Failed to new recog state machine " APT_SIDRES_FMT,
				MRCP_MESSAGE_SIDRES(request)
			);

			break;
		}

		recog_channel->asr_session = new PFMSC::ASRSession;
		if (recog_channel->asr_session == NULL)
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_WARNING,
				"Failed to new PFMSC::ASRSession " APT_SIDRES_FMT,
				MRCP_MESSAGE_SIDRES(request)
			);

			break;
		}
		recog_channel->asr_session->paramsSys = g_dftParamsSys;
		recog_channel->asr_session->paramsVendor = g_dftParamsVendor;
		recog_channel->asr_session->paramsASR = g_dftParamsASR;

		mrcp_generic_header_t*	req_generic_header = (mrcp_generic_header_t*)mrcp_generic_header_get(request);
		if (req_generic_header != NULL) {
			/* check vendor specific parameters */
			if (mrcp_generic_header_property_check(request, GENERIC_HEADER_VENDOR_SPECIFIC_PARAMS))
			{
				// update Session Key
				apt_str_t session_key_name;
				apt_string_set(&session_key_name, "session_key");
				const apt_pair_t* session_key = apt_pair_array_find(req_generic_header->vendor_specific_params, &session_key_name);
				if (session_key != NULL)
				{
					recog_channel->asr_session->strSessionKey.assign(session_key->value.buf);

					apt_log(RECOG_LOG_MARK, APT_PRIO_INFO,
						"uasrrecog - uasr_recog_channel_recognize() session_key updated to %s.",
						recog_channel->asr_session->strSessionKey.c_str()
					);
				}

				// update VadEos
				apt_str_t vad_eos_name;
				apt_string_set(&vad_eos_name, "vad_eos");
				const apt_pair_t* vad_eos = apt_pair_array_find(req_generic_header->vendor_specific_params, &vad_eos_name);
				if (vad_eos != NULL)
				{
					recog_channel->asr_session->paramsASR.nVadEos = atoi(vad_eos->value.buf);

					apt_log(RECOG_LOG_MARK, APT_PRIO_INFO,
						"uasrrecog - uasr_recog_channel_recognize() vad_eos updated to %d.",
						recog_channel->asr_session->paramsASR.nVadEos
					);
				}
			}
		}

		if (PFMSC::ASRStartSession(recog_channel->asr_session, uasr_recog_sm_on_notify, recog_channel) != PF::E_Errno_SUCCESS)
		{
			apt_log(RECOG_LOG_MARK, APT_PRIO_WARNING,
				"Failed to start PFMSC::ASRSession " APT_SIDRES_FMT,
				MRCP_MESSAGE_SIDRES(request)
			);

			break;
		}

		nRet = PF::E_Errno_SUCCESS;
	}
	if (nRet != PF::E_Errno_SUCCESS)
	{
		if (recog_channel->asr_session != NULL)
		{
			PFMSC::ASRStopSession(recog_channel->asr_session);
			delete recog_channel->asr_session;
			recog_channel->asr_session = NULL;
		}
		if (recog_channel->recog_sm != NULL)
		{
			delete recog_channel->recog_sm;
			recog_channel->recog_sm = NULL;
		}

		response->start_line.status_code = MRCP_STATUS_CODE_RESOURCE_SPECIFIC_FAILURE;
		return FALSE;
	}

	response->start_line.request_state = MRCP_REQUEST_STATE_INPROGRESS;
	/* send asynchronous response */
	mrcp_engine_channel_message_send(channel,response);
	recog_channel->recog_request = request;
	return TRUE;
}

/** Process STOP request */
static apt_bool_t uasr_recog_channel_stop(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	/* process STOP request */
	uasr_recog_channel_t *recog_channel = (uasr_recog_channel_t*)channel->method_obj;
	/* store STOP request, make sure there is no more activity and only then send the response */
	recog_channel->stop_response = response;
	return TRUE;
}

/** Process START-INPUT-TIMERS request */
static apt_bool_t uasr_recog_channel_timers_start(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	uasr_recog_channel_t *recog_channel = (uasr_recog_channel_t*)channel->method_obj;
	recog_channel->timers_started = TRUE;
	return mrcp_engine_channel_message_send(channel,response);
}

/** Dispatch MRCP request */
static apt_bool_t uasr_recog_channel_request_dispatch(mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_INFO, "uasr_recog_channel_request_dispatch() with method_id[%d].",
		request->start_line.method_id
		);

	apt_bool_t processed = FALSE;
	mrcp_message_t *response = mrcp_response_create(request,request->pool);
	switch(request->start_line.method_id) {
		case RECOGNIZER_SET_PARAMS:
			break;
		case RECOGNIZER_GET_PARAMS:
			break;
		case RECOGNIZER_DEFINE_GRAMMAR:
			break;
		case RECOGNIZER_RECOGNIZE:
			processed = uasr_recog_channel_recognize(channel,request,response);
			break;
		case RECOGNIZER_GET_RESULT:
			break;
		case RECOGNIZER_START_INPUT_TIMERS:
			processed = uasr_recog_channel_timers_start(channel,request,response);
			break;
		case RECOGNIZER_STOP:
			processed = uasr_recog_channel_stop(channel,request,response);
			break;
		default:
			break;
	}
	if(processed == FALSE) {
		/* send asynchronous response for not handled request */
		mrcp_engine_channel_message_send(channel,response);
	}
	return TRUE;
}

/** Callback is called from MPF engine context to destroy any additional data associated with audio stream */
static apt_bool_t uasr_recog_stream_destroy(mpf_audio_stream_t *stream)
{
	return TRUE;
}

/** Callback is called from MPF engine context to perform any action before open */
static apt_bool_t uasr_recog_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec)
{
	return TRUE;
}

/** Callback is called from MPF engine context to perform any action after close */
static apt_bool_t uasr_recog_stream_close(mpf_audio_stream_t *stream)
{
	uasr_recog_channel_t *recog_channel = (uasr_recog_channel_t*)stream->obj;
	if (recog_channel != NULL)
	{
		if (recog_channel->asr_session != NULL)
		{
			PFMSC::ASRStopSession(recog_channel->asr_session);
			delete recog_channel->asr_session;
			recog_channel->asr_session = NULL;
		}

		if (recog_channel->recog_sm != NULL)
		{
			delete recog_channel->recog_sm;
			recog_channel->recog_sm = NULL;
		}

		apt_log(RECOG_LOG_MARK, APT_PRIO_INFO,
			"uasr_recog_channel_stop() invoked."
		);
	}

	return TRUE;
}

/* Raise uasr START-OF-INPUT event */
static apt_bool_t uasr_recog_start_of_input(uasr_recog_channel_t *recog_channel)
{
	/* create START-OF-INPUT event */
	mrcp_message_t *message = mrcp_event_create(
						recog_channel->recog_request,
						RECOGNIZER_START_OF_INPUT,
						recog_channel->recog_request->pool);
	if(!message) {
		return FALSE;
	}

	/* set request state */
	message->start_line.request_state = MRCP_REQUEST_STATE_INPROGRESS;
	/* send asynch event */
	return mrcp_engine_channel_message_send(recog_channel->channel,message);
}

/* Load uasr recognition result */
static apt_bool_t uasr_recog_result_load(uasr_recog_channel_t *recog_channel, mrcp_message_t *message)
{
	apt_str_t	*body = &message->body;
	body->buf = NULL;
	body->length = 0;

	if (recog_channel->recog_sm != NULL)
	{
		body->buf = apr_psprintf(message->pool, "%s", recog_channel->recog_sm->strAsrResult.c_str());
	}

	if (body->buf != NULL) {
		body->length = strlen(body->buf);

		mrcp_generic_header_t *generic_header;

		/* get/allocate generic header */
		generic_header = mrcp_generic_header_prepare(message);
		if(generic_header) {
			/* set content types */
			apt_string_assign(&generic_header->content_type,"application/x-nlsml",message->pool);
			mrcp_generic_header_property_add(message,GENERIC_HEADER_CONTENT_TYPE);
		}
	}
	return TRUE;
}

/* Raise uasr RECOGNITION-COMPLETE event */
static apt_bool_t uasr_recog_recognition_complete(uasr_recog_channel_t *recog_channel, mrcp_recog_completion_cause_e cause)
{
	mrcp_recog_header_t *recog_header;
	/* create RECOGNITION-COMPLETE event */
	mrcp_message_t *message = mrcp_event_create(
						recog_channel->recog_request,
						RECOGNIZER_RECOGNITION_COMPLETE,
						recog_channel->recog_request->pool);
	if(!message) {
		return FALSE;
	}

	/* get/allocate recognizer header */
	recog_header = (mrcp_recog_header_t*)mrcp_resource_header_prepare(message);
	if(recog_header) {
		/* set completion cause */
		recog_header->completion_cause = cause;
		mrcp_resource_header_property_add(message,RECOGNIZER_HEADER_COMPLETION_CAUSE);
	}
	/* set request state */
	message->start_line.request_state = MRCP_REQUEST_STATE_COMPLETE;

	if(cause == RECOGNIZER_COMPLETION_CAUSE_SUCCESS) {
		uasr_recog_result_load(recog_channel,message);
	}

	recog_channel->recog_request = NULL;
	/* send asynch event */
	return mrcp_engine_channel_message_send(recog_channel->channel,message);
}

/** Callback is called from MPF engine context to write/send new frame */
static apt_bool_t uasr_recog_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame)
{
	uasr_recog_channel_t *recog_channel = (uasr_recog_channel_t*)stream->obj;
	if(recog_channel->stop_response) {
		/* send asynchronous response to STOP request */
		mrcp_engine_channel_message_send(recog_channel->channel,recog_channel->stop_response);
		recog_channel->stop_response = NULL;
		recog_channel->recog_request = NULL;
		return TRUE;
	}

	if(recog_channel->recog_request) {
		if (recog_channel->asr_session)
		{
			PFMSC::ASRFeedAudioData(recog_channel->asr_session, (const char*)frame->codec_frame.buffer, frame->codec_frame.size);
		}

		if (recog_channel->recog_sm)
		{
			uasr_recog_event_et	recog_event = uasr_recog_sm_get_status(recog_channel->recog_sm);
			switch (recog_event)
			{
			case uasr_recog_event_e_BeginSpeaking:
			{
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,
					"First Activity Sample detected, event(\"begin-speaking\") should be emitted " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request)
					);
				uasr_recog_start_of_input(recog_channel);

				break;
			}
			case uasr_recog_event_e_SpeechDetected:
			{
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,
					"EOS detected, event(\"speech-detected\") should be emitted " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request)
					);
				uasr_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_SUCCESS);

				break;
			}
			case uasr_recog_event_e_TimeoutNoInput:
			{
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,
					"Detected Noinput " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request)
					);
				uasr_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_NO_INPUT_TIMEOUT);

				break;
			}
			case uasr_recog_event_e_TimeoutDetecting:
			{
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,
					"Detected Too Much " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request)
					);
				uasr_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_TOO_MUCH_SPEECH_TIMEOUT);

				break;
			}
			case uasr_recog_event_e_Error:
			{
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,
					"Detected Error " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request)
					);
				uasr_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_ERROR);

				break;
			}
			default:
				break;
			}
		}

		if(recog_channel->recog_request) {
			if((frame->type & MEDIA_FRAME_TYPE_EVENT) == MEDIA_FRAME_TYPE_EVENT) {
				if(frame->marker == MPF_MARKER_START_OF_EVENT) {
					apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Start of Event " APT_SIDRES_FMT " id:%d",
						MRCP_MESSAGE_SIDRES(recog_channel->recog_request),
						frame->event_frame.event_id);
				}
				else if(frame->marker == MPF_MARKER_END_OF_EVENT) {
					apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected End of Event " APT_SIDRES_FMT " id:%d duration:%d ts",
						MRCP_MESSAGE_SIDRES(recog_channel->recog_request),
						frame->event_frame.event_id,
						frame->event_frame.duration);
				}
			}
		}
	}
	return TRUE;
}

static apt_bool_t uasr_recog_msg_signal(uasr_recog_msg_type_e type, mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_bool_t status = FALSE;
	uasr_recog_channel_t *uasr_channel = (uasr_recog_channel_t*)channel->method_obj;
	uasr_recog_engine_t *uasr_engine = (uasr_recog_engine_t*)uasr_channel->uasr_engine;
	apt_task_t *task = apt_consumer_task_base_get(uasr_engine->task);
	apt_task_msg_t *msg = apt_task_msg_get(task);
	if(msg) {
		uasr_recog_msg_t *uasr_msg;
		msg->type = TASK_MSG_USER;
		uasr_msg = (uasr_recog_msg_t*) msg->data;

		uasr_msg->type = type;
		uasr_msg->channel = channel;
		uasr_msg->request = request;
		status = apt_task_msg_signal(task,msg);
	}
	return status;
}

static apt_bool_t uasr_recog_msg_process(apt_task_t *task, apt_task_msg_t *msg)
{
	uasr_recog_msg_t *uasr_msg = (uasr_recog_msg_t*)msg->data;
	switch(uasr_msg->type) {
		case UASR_RECOG_MSG_OPEN_CHANNEL:
			/* open channel and send asynch response */
			mrcp_engine_channel_open_respond(uasr_msg->channel,TRUE);
			break;
		case UASR_RECOG_MSG_CLOSE_CHANNEL:
		{
			mrcp_engine_channel_close_respond(uasr_msg->channel);
			break;
		}
		case UASR_RECOG_MSG_REQUEST_PROCESS:
			uasr_recog_channel_request_dispatch(uasr_msg->channel,uasr_msg->request);
			break;
		default:
			break;
	}
	return TRUE;
}

static int32_t				uasr_recog_sm_on_notify(void* pvContext, uint32_t uAsrStatus, const char* pstrAsrResult)
{
	uasr_recog_channel_t* recog_channel = (uasr_recog_channel_t*)pvContext;
	uasr_recog_state_machine_t*	recog_sm = recog_channel->recog_sm;
	PFMSC::ASRSession* asr_session = recog_channel->asr_session;

	switch (uAsrStatus)
	{
	case PFMSC_ASR_STATUS_DETECTING:
	{ // 1st frame detected, should send begin-speaking event
		PFGuard< PFThreadMutex >	guard(recog_sm->mutexAsrStatus);
		if (recog_sm->uAsrStatus != uAsrStatus)
		{
			recog_sm->uAsrStatus = uAsrStatus;
			recog_sm->lluTimeBeginSpeaking = time(NULL);
		}

		break;
	}
	case PFMSC_ASR_STATUS_DETECTED:
	{ // speech detected, should send speech detected event
		PFGuard< PFThreadMutex >	guard(recog_sm->mutexAsrStatus);
		if (recog_sm->uAsrStatus != uAsrStatus)
		{
			recog_sm->uAsrStatus = uAsrStatus;
			recog_sm->strAsrResult.assign(asr_session->paramsASR.strResultFormat);
			PF::ReplaceString(recog_sm->strAsrResult, "${result}", pstrAsrResult);
			recog_sm->lluTimeSpeechDetected = time(NULL);
		}

		break;
	}
	case PFMSC_ASR_STATUS_INVALID:
	{ // error
		PFGuard< PFThreadMutex >	guard(recog_sm->mutexAsrStatus);
		if (recog_sm->uAsrStatus != uAsrStatus)
		{
			recog_sm->uAsrStatus = uAsrStatus;
		}

		break;
	}
	default:
	{
		break;
	}
	}
}

static uasr_recog_event_et	uasr_recog_sm_get_status(uasr_recog_state_machine_t* recog_sm)
{
	uasr_recog_event_et	recog_event = uasr_recog_event_e_Ignore;

	uint64_t	lluTimeNow = time(NULL);

	PFGuard< PFThreadMutex >	guard(recog_sm->mutexAsrStatus);
	switch (recog_sm->uAsrStatus)
	{
	case PFMSC_ASR_STATUS_FEEDING:
	case PFMSC_ASR_STATUS_LOOKING:
	{
		// check if TimeoutNoInput
		if ((lluTimeNow - recog_sm->lluTimeBeginSession) >= recog_sm->uTimeoutNoInput)
		{
			recog_event = uasr_recog_event_e_TimeoutNoInput;
		}

		break;
	}
	case PFMSC_ASR_STATUS_DETECTING:
	{ // 1st frame detected, should send begin-speaking event
		// check if TimeoutDetecting
		if ((lluTimeNow - recog_sm->lluTimeBeginSpeaking) >= recog_sm->uTimeoutDetecting)
		{
			recog_event = uasr_recog_event_e_TimeoutDetecting;
			break;
		}

		if (recog_sm->uAsrStatusPrev != recog_sm->uAsrStatus)
		{
			recog_sm->uAsrStatusPrev = recog_sm->uAsrStatus;
			recog_event = uasr_recog_event_e_BeginSpeaking;
		}

		break;
	}
	case PFMSC_ASR_STATUS_DETECTED:
	{ // speech detected, should send speech-detected event
		if (recog_sm->uAsrStatusPrev != recog_sm->uAsrStatus)
		{
			recog_sm->uAsrStatusPrev = recog_sm->uAsrStatus;
			recog_event = uasr_recog_event_e_SpeechDetected;
		}

		break;
	}
	case PFMSC_ASR_STATUS_INVALID:
	default:
	{ // error
		if (recog_sm->uAsrStatusPrev != recog_sm->uAsrStatus)
		{
			recog_sm->uAsrStatusPrev = recog_sm->uAsrStatus;
			recog_event = uasr_recog_event_e_Error;
		}

		break;
	}
	}

	return recog_event;
}

