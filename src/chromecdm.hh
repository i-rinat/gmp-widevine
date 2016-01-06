#pragma once

#include <stdlib.h>
#include <crcdm/content_decryption_module.h>


namespace crcdm {

void
Initialize();

void
Deinitialize();

cdm::ContentDecryptionModule *
CreateInstance();

} // namespace crcdm
