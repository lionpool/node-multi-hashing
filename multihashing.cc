#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"


extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    // news algos added by nosekefik
    #include "phi1612.h"
    #include "tribus.h"
    #include "blake2s.h"
    #include "gost.h"
    #include "Lyra2RE.h"
    #include "Lyra2.h"
    #include "Lyra2REV2.h"
    #include "Lyra2Z.h"
    #include "neoscrypt.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "hsr14.h"
    #include "skunk.h"
    #include "lyra2z330.h"
    #include "lyra2z16m330.h"
    #include "m7.h"
  //  #include "m7m.h"
    #include "magimath.h"
    #include "xevan.h"
// not sure if it works. too easy to be true 8/. Lion
    #include "x14.h"	
    #include "x17.h"
}

#include "boolberry.h"

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

using namespace node;
using namespace v8;


NAN_METHOD(quark) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x11) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scrypt) {

   if (info.Length() < 3)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash, N value, and R value");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");
    
   Local<Number> numn = Nan::To<Number>(info[1]).ToLocalChecked();
   unsigned int nValue = numn->Value();
   Local<Number> numr = Nan::To<Number>(info[2]).ToLocalChecked();
   unsigned int rValue = numr->Value();
   
   char * input = Buffer::Data(target);
   char *output = (char*) malloc(sizeof(char) * 32);

   uint32_t input_len = Buffer::Length(target);
   
   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}



NAN_METHOD(scryptn) {

   if (info.Length() < 2)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash and N factor.");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

   Local<Number> num = Nan::To<Number>(info[1]).ToLocalChecked();
   unsigned int nFactor = num->Value();

   char* input = Buffer::Data(target);
   //char output[32]; // Node tries to free this later on but can't and causes a malloc error
   char *output = (char*) malloc(sizeof(char) * 32);

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;
   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scryptjane) {

    if (info.Length() < 5)
        return THROW_ERROR_EXCEPTION("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("First should be a buffer object.");

    Local<Number> num = Nan::To<Number>(info[1]).ToLocalChecked();
    int timestamp = num->Value();

    Local<Number> num2 = Nan::To<Number>(info[2]).ToLocalChecked();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = Nan::To<Number>(info[3]).ToLocalChecked();
    int nMin = num3->Value();

    Local<Number> num4 = Nan::To<Number>(info[4]).ToLocalChecked();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(keccak) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(bcrypt) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    bcrypt_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(skein) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char *input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);
    
    skein_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(groestl) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char *input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(groestlmyriad) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(blake) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(fugue) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(qubit) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(hefty1) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(shavite3) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(cryptonight) {

    bool fast = false;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
        fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x13) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(boolberry) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    Local<Object> target_spad = Nan::To<Object>(info[1]).ToLocalChecked();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

    if(info.Length() >= 3) {
        if(info[2]->IsUint32()) {
            height = info[2]->ToUint32()->Uint32Value(); // TODO: This does not like Nan::To<uint32_t>(), the current way is deprecated
        } else {
            return THROW_ERROR_EXCEPTION("Argument 3 should be an unsigned integer.");
        }
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(nist5) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(sha1) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x14) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x15) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(fresh) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

// new algos added by nosekefik
NAN_METHOD(phi1612) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    phi1612_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(tribus) {

    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    tribus_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());

}
NAN_METHOD(blake2s) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    blake2s_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(gost) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    gost_hash(input, output,input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());

}

NAN_METHOD(lyra2re) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    lyra2re_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());

}

NAN_METHOD(lyra2rev2) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);    
    lyra2re2_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());

}

NAN_METHOD(lyra2z) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    lyra2z_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(neoscrypt) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

     char *input =  ( char*) Buffer::Data(target);
     char *output = ( char*) malloc(sizeof(char) * 32);
     
//    uint32_t input_len = Buffer::Length(target);
    neoscrypt(input, output,0);
    
    info.GetReturnValue().Set(Nan::NewBuffer( (char*)output, 32).ToLocalChecked());
}
NAN_METHOD(yescrypt) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
	
	yescrypt_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(hsr) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t len = Buffer::Length(target);
	hsr_hash(input, output,len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(skunk) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);
    
	skunk_hash(input, output,0);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(lyra2z330) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    lyra2z330_hash(input, output,input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2z16m330) {
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    lyra2z16m330_hash(input, output,input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(m7){
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    m7_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(m7m){
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(sizeof(char) * 32);

    m7_hash_magi(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(xevan){
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(sizeof(char) * 32);
    
    uint32_t input_len = Buffer::Length(target);
    xevan_hash(input, output,input_len);
    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x17){
    if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char * output = (char*) malloc(sizeof(char) * 32);
   
    uint32_t input_len = Buffer::Length(target);
    x17_hash(input, output,input_len);
    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("quark").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(quark)).ToLocalChecked());
    Nan::Set(target, Nan::New("x11").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x11)).ToLocalChecked());
    Nan::Set(target, Nan::New("scrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptn").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptn)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptjane").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptjane)).ToLocalChecked());
    Nan::Set(target, Nan::New("keccak").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(keccak)).ToLocalChecked());
    Nan::Set(target, Nan::New("bcrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(bcrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("skein").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(skein)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestl").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestl)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestlmyriad").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
    Nan::Set(target, Nan::New("blake").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(blake)).ToLocalChecked());
    Nan::Set(target, Nan::New("fugue").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fugue)).ToLocalChecked());
    Nan::Set(target, Nan::New("qubit").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(qubit)).ToLocalChecked());
    Nan::Set(target, Nan::New("hefty1").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(hefty1)).ToLocalChecked());
    Nan::Set(target, Nan::New("shavite3").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(shavite3)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("x13").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x13)).ToLocalChecked());
    Nan::Set(target, Nan::New("boolberry").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(boolberry)).ToLocalChecked());
    Nan::Set(target, Nan::New("nist5").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(nist5)).ToLocalChecked());
    Nan::Set(target, Nan::New("sha1").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(sha1)).ToLocalChecked());
    Nan::Set(target, Nan::New("x15").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x15)).ToLocalChecked());
    Nan::Set(target, Nan::New("fresh").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fresh)).ToLocalChecked());
	
 // new algos added by nosekefik
    Nan::Set(target, Nan::New("phi1612").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(phi1612)).ToLocalChecked());    
    Nan::Set(target, Nan::New("tribus").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(tribus)).ToLocalChecked());
    Nan::Set(target, Nan::New("blake2s").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(blake2s)).ToLocalChecked());
    Nan::Set(target, Nan::New("gost").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(gost)).ToLocalChecked());
    Nan::Set(target, Nan::New("lyra2re").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(lyra2re)).ToLocalChecked());
    Nan::Set(target, Nan::New("lyra2rev2").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(lyra2rev2)).ToLocalChecked());
    Nan::Set(target, Nan::New("lyra2z").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(lyra2z)).ToLocalChecked());
    Nan::Set(target, Nan::New("neoscrypt").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(neoscrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("yescrypt").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(yescrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("hsr").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(hsr)).ToLocalChecked());
    Nan::Set(target, Nan::New("skunk").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(skunk)).ToLocalChecked());
    Nan::Set(target, Nan::New("lyra2z330").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(lyra2z330)).ToLocalChecked());
    Nan::Set(target, Nan::New("lyra2z16m330").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(lyra2z16m330)).ToLocalChecked());
    Nan::Set(target, Nan::New("m7").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(m7)).ToLocalChecked());
    Nan::Set(target, Nan::New("m7m").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(m7m)).ToLocalChecked());
    Nan::Set(target, Nan::New("xevan").ToLocalChecked(),Nan::GetFunction(Nan::New<v8::FunctionTemplate>(xevan)).ToLocalChecked());
	
// added x14 & x17. not sure if it works. Lion
    Nan::Set(target, Nan::New("x14").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(x14)).ToLocalChecked());
    Nan::Set(target, Nan::New("x17").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(x17)).ToLocalChecked()); 

   
}


NODE_MODULE(multihashing, init)
