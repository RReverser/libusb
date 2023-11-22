extern "C" {
#include <umockdev-server.h>
}

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
	auto chats =
		reinterpret_cast<UsbChat*>(info[1].As<Napi::Uint8Array>().Data());
	test_fixture_set_chats(GetFixtureArg(info), chats);
	return {};
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	exports.Set("setupMocking", Napi::Function::New(env, SetupMocking));
	exports.Set("teardownMocking", Napi::Function::New(env, TeardownMocking));
	exports.Set("addCanon", Napi::Function::New(env, AddCanon));
	exports.Set("setChats", Napi::Function::New(env, SetChats));
	return exports;
}

NODE_API_MODULE(addon, Init)
