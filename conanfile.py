from conans import ConanFile, CMake

class PoorProfConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake", "gcc", "txt"

    requires = "fmt/7.1.3", "elfutils/0.180", "spdlog/1.8.5", "abseil/20210324.1"

    options = {
        "pkg": "ANY",
    }

    default_options = {
        "pkg": "kek",
    }

    def configure(self):
        # self.options['backward-cpp'].shared = False
        # self.options['backward-cpp'].stack_details = 'dw'
        # self.options['backward-cpp'].stack_walking = 'unwind'
        pass

    def requirements(self):
        pass
        # self.requires(str(self.options.pkg))

    def imports(self):
        self.copy("*.dll", dst="bin", src="bin")
        self.copy("*.dylib*", dst="bin", src="lib")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
