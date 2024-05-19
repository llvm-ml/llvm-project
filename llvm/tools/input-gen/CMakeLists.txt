set(LLVM_LINK_COMPONENTS
  Core
  BitWriter
  IRReader
  Support
  IPO
  Passes
  Analysis
  TransformUtils
  TargetParser
  )



add_llvm_tool(input-gen
  input-gen.cpp
  PARTIAL_SOURCES_INTENDED

  DEPENDS
  )

add_llvm_tool(mbb-pgo-info
  mbb-pgo-info.cpp
  PARTIAL_SOURCES_INTENDED

  DEPENDS
  )
