

Pod::Spec.new do |spec|

  spec.name         = "NetworkBaseds"
  spec.version      = "0.0.2"
  spec.summary      = "NetworkBaseds"
  spec.description  = <<-DESC
                    组件库测试
                   DESC

  spec.homepage     = "http://EXAMPLE/NetworkBaseds"
  spec.license      = { :type => "MIT", :file => "FILE_LICENSE" }

  spec.author             = { "谢雪滔" => "xie_xuetao@163.com" }
  spec.authors            = { "谢雪滔" => "xie_xuetao@163.com" }
  spec.social_media_url   = "https://twitter.com/谢雪滔"

  # spec.platform     = :ios
  # spec.platform     = :ios, "5.0"

  spec.source       = { :git => "https://github.com/xiexuetao/NetworkBaseds.git", :tag => "#{spec.version}" }

  spec.source_files  = "Classes", "Classes/**/*.{h,m}"
  #spec.exclude_files = "Classes/Exclude"

  # spec.public_header_files = "Classes/**/*.h"


  # ――― Resources ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  A list of resources included with the Pod. These are copied into the
  #  target bundle with a build phase script. Anything else will be cleaned.
  #  You can preserve files from being cleaned, please don't preserve
  #  non-essential files like tests, examples and documentation.
  #

  # spec.resource  = "icon.png"
  # spec.resources = "Resources/*.png"

  # spec.preserve_paths = "FilesToSave", "MoreFilesToSave"


  # ――― Project Linking ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  Link your library with frameworks, or libraries. Libraries do not include
  #  the lib prefix of their name.
  #

  # spec.framework  = "SomeFramework"
  # spec.frameworks = "SomeFramework", "AnotherFramework"

  # spec.library   = "iconv"
  # spec.libraries = "iconv", "xml2"


  # ――― Project Settings ――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  If your library depends on compiler flags you can set them in the xcconfig hash
  #  where they will only apply to your library. If you depend on other Podspecs
  #  you can include multiple dependencies to ensure it works.

  spec.requires_arc = true

  # spec.xcconfig = { "HEADER_SEARCH_PATHS" => "$(SDKROOT)/usr/include/libxml2" }
  # spec.dependency "JSONKit", "~> 1.4"

end
