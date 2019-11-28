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
 * Demo synthesizer scenario.
 * C -> S: SIP INVITE or RTPS SETUP   (add synthesizer channel)
 * S -> C: SIP OK or RTPS OK
 * C -> S: MRCP SPEAK
 * S -> C: MRCP IN-PROGRESS
 * S -> C: RTP Start Transmission
 * S -> C: MRCP SPEAK-COMPLETE
 * S -> C: RTP Stop Transmission
 * C -> S: SIP INVITE or RTPS SETUP   (optionally remove synthesizer channel)
 * S -> C: SIP OK or RTPS OK
 * C -> S: SIP BYE or RTPS TEARDOWN
 * S -> C: SIP OK or RTPS OK
 */

#include "demo_application.h"
#include "demo_util.h"
#include "mrcp_message.h"
#include "mrcp_generic_header.h"
#include "mrcp_synth_header.h"
#include "mrcp_synth_resource.h"
#include "apt_log.h"
#include "main.h"

typedef struct synth_app_channel_t synth_app_channel_t;

/** Declaration of synthesizer application channel */
struct synth_app_channel_t {
	/** MRCP control channel */
	mrcp_channel_t *channel;
	/** File to write audio stream to */
	FILE           *audio_out;
};

/** Declaration of synthesizer application methods */
static apt_bool_t synth_application_run(demo_application_t *demo_application, const char *profile);
static apt_bool_t synth_application_handler(demo_application_t *application, const mrcp_app_message_t *app_message);

/** Declaration of application message handlers */
static apt_bool_t synth_application_on_session_update(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status);
static apt_bool_t synth_application_on_session_terminate(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status);
static apt_bool_t synth_application_on_channel_add(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status);
static apt_bool_t synth_application_on_channel_remove(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status);
static apt_bool_t synth_application_on_message_receive(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_message_t *message);

static const mrcp_app_message_dispatcher_t synth_application_dispatcher = {
	synth_application_on_session_update,
	synth_application_on_session_terminate,
	synth_application_on_channel_add,
	synth_application_on_channel_remove,
	synth_application_on_message_receive,
	NULL /* synth_application_on_terminate_event */,
	NULL /* synth_application_on_resource_discover */
};

/** Declaration of synthesizer audio stream methods */
static apt_bool_t synth_app_stream_destroy(mpf_audio_stream_t *stream);
static apt_bool_t synth_app_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec);
static apt_bool_t synth_app_stream_close(mpf_audio_stream_t *stream);
static apt_bool_t synth_app_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame);

static const mpf_audio_stream_vtable_t audio_stream_vtable = {
	synth_app_stream_destroy,
	NULL,
	NULL,
	NULL,
	synth_app_stream_open,
	synth_app_stream_close,
	synth_app_stream_write,
	NULL
};


/** Create demo synthesizer application */
demo_application_t* demo_synth_application_create(apr_pool_t *pool)
{
	demo_application_t *synth_application = apr_palloc(pool,sizeof(demo_application_t));
	synth_application->application = NULL;
	synth_application->framework = NULL;
	synth_application->handler = synth_application_handler;
	synth_application->run = synth_application_run;
	return synth_application;
}

/** Create demo synthesizer channel */
static mrcp_channel_t* synth_application_channel_create(mrcp_session_t *session)
{
	mrcp_channel_t *channel;
	mpf_termination_t *termination;
	mpf_stream_capabilities_t *capabilities;
	apr_pool_t *pool = mrcp_application_session_pool_get(session);

	/* create channel */
	synth_app_channel_t *synth_channel = apr_palloc(pool,sizeof(synth_app_channel_t));
	synth_channel->audio_out = NULL;

	/* create sink stream capabilities */
	capabilities = mpf_sink_stream_capabilities_create(pool);

	/* add codec capabilities (Linear PCM) */
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000 | MPF_SAMPLE_RATE_16000,
			"LPCM");

#if 0
	/* more capabilities can be added or replaced */
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000 | MPF_SAMPLE_RATE_16000,
			"PCMU");
#endif

	termination = mrcp_application_audio_termination_create(
			session,                   /* session, termination belongs to */
			&audio_stream_vtable,      /* virtual methods table of audio stream */
			capabilities,              /* capabilities of audio stream */
			synth_channel);            /* object to associate */
	
	channel = mrcp_application_channel_create(
			session,                   /* session, channel belongs to */
			MRCP_SYNTHESIZER_RESOURCE, /* MRCP resource identifier */
			termination,               /* media termination, used to terminate audio stream */
			NULL,                      /* RTP descriptor, used to create RTP termination (NULL by default) */
			synth_channel);            /* object to associate */
	return channel;
}

/**
 * Convert PCM16LE raw data to WAVE format
 * @param pcmpath       Input PCM file.
 * @param channels      Channel number of PCM file.
 * @param sample_rate   Sample rate of PCM file.
 * @param wavepath      Output WAVE file.
 */
int simplest_pcm16le_to_wave(const char *pcmpath, int channels, int sample_rate, const char *wavepath)
{
    typedef struct WAVE_HEADER{
        char    fccID[4];       //内容为""RIFF
        unsigned long dwSize;   //最后填写，WAVE格式音频的大小
        char    fccType[4];     //内容为"WAVE"
    }WAVE_HEADER;

    typedef struct WAVE_FMT{
        char    fccID[4];          //内容为"fmt "
        unsigned long  dwSize;     //内容为WAVE_FMT占的字节数，为16
        unsigned short wFormatTag; //如果为PCM，改值为 1
        unsigned short wChannels;  //通道数，单通道=1，双通道=2
        unsigned long  dwSamplesPerSec;//采用频率
        unsigned long  dwAvgBytesPerSec;/* ==dwSamplesPerSec*wChannels*uiBitsPerSample/8 */
        unsigned short wBlockAlign;//==wChannels*uiBitsPerSample/8
        unsigned short uiBitsPerSample;//每个采样点的bit数，8bits=8, 16bits=16
    }WAVE_FMT;

    typedef struct WAVE_DATA{
        char    fccID[4];       //内容为"data"
        unsigned long dwSize;   //==NumSamples*wChannels*uiBitsPerSample/8
    }WAVE_DATA;

    if(channels==2 || sample_rate==0)
    {
        channels = 2;
        sample_rate = 44100;
    }
    int bits = 16;

    WAVE_HEADER pcmHEADER;
    WAVE_FMT    pcmFMT;
    WAVE_DATA   pcmDATA;

    unsigned short m_pcmData;
    FILE *fp, *fpout;

    fp = fopen(pcmpath, "rb+");
    if(fp==NULL)
    {
        printf("Open pcm file error.\n");
        return -1;
    }
    fpout = fopen(wavepath, "wb+");
    if(fpout==NULL)
    {
        printf("Create wav file error.\n");
        return -1;
    }

    /* WAVE_HEADER */
    memcpy(pcmHEADER.fccID, "RIFF", strlen("RIFF"));
    memcpy(pcmHEADER.fccType, "WAVE", strlen("WAVE"));
    fseek(fpout, sizeof(WAVE_HEADER), 1);   //1=SEEK_CUR
    /* WAVE_FMT */
    memcpy(pcmFMT.fccID, "fmt ", strlen("fmt "));
    pcmFMT.dwSize = 16;
    pcmFMT.wFormatTag = 1;
    pcmFMT.wChannels = 2;
    pcmFMT.dwSamplesPerSec = sample_rate;
    pcmFMT.uiBitsPerSample = bits;
    /* ==dwSamplesPerSec*wChannels*uiBitsPerSample/8 */
    pcmFMT.dwAvgBytesPerSec = pcmFMT.dwSamplesPerSec*pcmFMT.wChannels*pcmFMT.uiBitsPerSample/8;
    /* ==wChannels*uiBitsPerSample/8 */
    pcmFMT.wBlockAlign = pcmFMT.wChannels*pcmFMT.uiBitsPerSample/8;


    fwrite(&pcmFMT, sizeof(WAVE_FMT), 1, fpout);

    /* WAVE_DATA */
    memcpy(pcmDATA.fccID, "data", strlen("data"));
    pcmDATA.dwSize = 0;
    fseek(fpout, sizeof(WAVE_DATA), SEEK_CUR);

    fread(&m_pcmData, sizeof(unsigned short), 1, fp);
    while(!feof(fp))
    {
        pcmDATA.dwSize += 2;
        fwrite(&m_pcmData, sizeof(unsigned short), 1, fpout);
        fread(&m_pcmData, sizeof(unsigned short), 1, fp);
    }

    /*pcmHEADER.dwSize = 44 + pcmDATA.dwSize;*/
    //修改时间：2018年1月5日
    pcmHEADER.dwSize = 36 + pcmDATA.dwSize;

    rewind(fpout);
    fwrite(&pcmHEADER, sizeof(WAVE_HEADER), 1, fpout);
    fseek(fpout, sizeof(WAVE_FMT), SEEK_CUR);
    fwrite(&pcmDATA, sizeof(WAVE_DATA), 1, fpout);

    fclose(fp);
    fclose(fpout);

    return 0;
}


/** Run demo synthesizer scenario */
static apt_bool_t synth_application_run(demo_application_t *demo_application, const char *profile)
{
	mrcp_channel_t *channel;
	/* create session */
	mrcp_session_t *session = mrcp_application_session_create(demo_application->application,profile,NULL);
	if(!session) {
		return FALSE;
	}
	
	/* create channel and associate all the required data */
	channel = synth_application_channel_create(session);
	if(!channel) {
		mrcp_application_session_destroy(session);
		return FALSE;
	}

	/* add channel to session (send asynchronous request) */
	if(mrcp_application_channel_add(session,channel) != TRUE) {
		/* session and channel are still not referenced 
		and both are allocated from session pool and will
		be freed with session destroy call */
		mrcp_application_session_destroy(session);
		return FALSE;
	}

	return TRUE;
}

/** Handle the messages sent from the MRCP client stack */
static apt_bool_t synth_application_handler(demo_application_t *application, const mrcp_app_message_t *app_message)
{
	/* app_message should be dispatched now,
	*  the default dispatcher is used in demo. */
	return mrcp_application_message_dispatch(&synth_application_dispatcher,app_message);
}

/** Handle the responses sent to session update requests */
static apt_bool_t synth_application_on_session_update(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	/* not used in demo */
	return TRUE;
}

/** Handle the responses sent to session terminate requests */
static apt_bool_t synth_application_on_session_terminate(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	/* received response to session termination request,
	now it's safe to destroy no more referenced session */
	mrcp_application_session_destroy(session);
	return TRUE;
}

/** Handle the responses sent to channel add requests */
static apt_bool_t synth_application_on_channel_add(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	if(status == MRCP_SIG_STATUS_CODE_SUCCESS) {
		mrcp_message_t *mrcp_message;
		synth_app_channel_t *synth_channel = mrcp_application_channel_object_get(channel);
		apr_pool_t *pool = mrcp_application_session_pool_get(session);
		const apt_dir_layout_t *dir_layout = mrcp_application_dir_layout_get(application);
		const mpf_codec_descriptor_t *descriptor = mrcp_application_sink_descriptor_get(channel);
		if(!descriptor) {
			/* terminate the demo */
			apt_log(APT_LOG_MARK,APT_PRIO_WARNING,"Failed to Get Media Sink Descriptor");
			return mrcp_application_session_terminate(session);
		}

		/* create and send SPEAK request */
		mrcp_message = demo_speak_message_create(session,channel,dir_layout);
		if(mrcp_message) {
			mrcp_application_message_send(session,channel,mrcp_message);
		}

		if(synth_channel) {
			const apt_str_t *id = mrcp_application_session_id_get(session);
			//char *file_name = apr_psprintf(pool,"%s.pcm",
			//						g_wavfile);
			//char *file_path = apt_vardir_filepath_get(dir_layout,file_name,pool);
			char* file_path = g_pcmfile;
			if(file_path) {
				apt_log(APT_LOG_MARK,APT_PRIO_INFO,"Open Speech Output File [%s] for Writing",file_path);
				synth_channel->audio_out = fopen(file_path,"wb");
				if(!synth_channel->audio_out) {
					apt_log(APT_LOG_MARK,APT_PRIO_WARNING,"Failed to Open Utterance Output File [%s] for Writing",file_path);
				}
			}
		}
	}
	else {
		/* error case, just terminate the demo */
		mrcp_application_session_terminate(session);
	}
	return TRUE;
}

/** Handle the responses sent to channel remove requests */
static apt_bool_t synth_application_on_channel_remove(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	synth_app_channel_t *synth_channel = mrcp_application_channel_object_get(channel);

	/* terminate the demo */
	mrcp_application_session_terminate(session);

	if(synth_channel) {
		FILE *audio_out = synth_channel->audio_out;
		if(audio_out) {
			synth_channel->audio_out = NULL;
			fclose(audio_out);
		}
		simplest_pcm16le_to_wave(g_pcmfile,1,8000,g_wavfile);
		printf("pcm over!\n");
		exit(-3);
	}
	return TRUE;
}

/** Handle the MRCP responses/events */
static apt_bool_t synth_application_on_message_receive(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_message_t *message)
{
	if(message->start_line.message_type == MRCP_MESSAGE_TYPE_RESPONSE) {
		/* received MRCP response */
		if(message->start_line.method_id == SYNTHESIZER_SPEAK) {
			/* received the response to SPEAK request */
			if(message->start_line.request_state == MRCP_REQUEST_STATE_INPROGRESS) {
				/* waiting for SPEAK-COMPLETE event */
			}
			else {
				/* received unexpected response, remove channel */
				mrcp_application_channel_remove(session,channel);
			}
		}
		else {
			/* received unexpected response */
		}
	}
	else if(message->start_line.message_type == MRCP_MESSAGE_TYPE_EVENT) {
		/* received MRCP event */
		if(message->start_line.method_id == SYNTHESIZER_SPEAK_COMPLETE) {
			/* received SPEAK-COMPLETE event, remove channel */
			mrcp_application_channel_remove(session,channel);
		}
	}
	return TRUE;
}

/** Callback is called from MPF engine context to destroy any additional data associated with audio stream */
static apt_bool_t synth_app_stream_destroy(mpf_audio_stream_t *stream)
{
	/* nothing to destroy in demo */
	return TRUE;
}

/** Callback is called from MPF engine context to perform application stream specific action before open */
static apt_bool_t synth_app_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec)
{
	return TRUE;
}

/** Callback is called from MPF engine context to perform application stream specific action after close */
static apt_bool_t synth_app_stream_close(mpf_audio_stream_t *stream)
{
	return TRUE;
}

/** Callback is called from MPF engine context to make new frame available to write/send */
static apt_bool_t synth_app_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame)
{
	synth_app_channel_t *synth_channel = stream->obj;
	if(synth_channel && synth_channel->audio_out) {
		fwrite(frame->codec_frame.buffer,1,frame->codec_frame.size,synth_channel->audio_out);
	}
	return TRUE;
}
