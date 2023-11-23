#include "../umockdev-server.h"

#include <napi.h>

static MockingFixture* GetFixtureArg(const Napi::CallbackInfo& info) {
	bool lossless;
	return reinterpret_cast<MockingFixture*>(
		info[0].As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value SetupMocking(const Napi::CallbackInfo& info) {
	return Napi::Value::From(
		info.Env(), reinterpret_cast<uint64_t>(test_fixture_setup_mocking()));
}

Napi::Value TeardownMocking(const Napi::CallbackInfo& info) {
	test_fixture_teardown_mocking(GetFixtureArg(info));
	return {};
}

Napi::Value AddCanon(const Napi::CallbackInfo& info) {
	test_fixture_add_canon(GetFixtureArg(info));
	return {};
}

Napi::Value SetChats(const Napi::CallbackInfo& info) {
	auto wasm_mem_start = info.Env()
							  .Global()
							  .Get("wasmMemory")
							  .ToObject()
							  .Get("buffer")
							  .As<Napi::ArrayBuffer>()
							  .Data();
	auto chats_data =
		reinterpret_cast<UsbChat*>(wasm_mem_start + chats_raw.Data());
	auto chats_len = chats_raw.ByteLength() / sizeof(UsbChat);
	// Adjust pointers from Wasm to native.
	for (size_t i = 0; i < chats_len; i++) {
		chats_data[i].buffer = wasm_mem_start + chats_data[i].buffer_ptr;
	}
	test_fixture_set_chats(GetFixtureArg(info), chats_data, chats_len);
	return {};
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	exports.Set("test_fixture_setup_mocking",
				Napi::Function::New(env, SetupMocking));
	exports.Set("test_fixture_teardown_mocking",
				Napi::Function::New(env, TeardownMocking));
	exports.Set("test_fixture_add_canon", Napi::Function::New(env, AddCanon));
	exports.Set("test_fixture_set_chats", Napi::Function::New(env, SetChats));
	return exports;
}

NODE_API_MODULE(addon, Init)
