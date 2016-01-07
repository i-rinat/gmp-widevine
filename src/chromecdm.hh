#pragma once

#include <stdlib.h>
#include <crcdm/content_decryption_module.h>
#include <gmp/gmp-decryption.h>


namespace crcdm {

void
Initialize();

void
Deinitialize();

cdm::ContentDecryptionModule *
CreateInstance(GMPDecryptorCallback *decryptor_cb);

} // namespace crcdm
