#include <iostream>
#include <napi.h>

Napi::Object InitAll(Napi::Env env, Napi::Object exports)
{
	/* //export for 'demo' script:
	exports.Set(Napi::String::New(env, "calculateSync"),
				Napi::Function::New(env, CalculateSync));

	//the light API version
	exports.Set(Napi::String::New(env, "generateHomomorficContext"),
				Napi::Function::New(env, nsSEALWrapper::generateHomomorficContext)); //factory
	nsSEALWrapper::HomomorphicContextWrapper::Init(env, exports); */

	return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, InitAll)