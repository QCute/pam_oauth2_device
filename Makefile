CXXFLAGS=-Wall -flto -o3 -fPIC -std=c++11

LDLIBS=-lpam -lcurl

objects = src/pam_oauth2_device.o src/QR-Code-generator/cpp/qrcodegen.o

all: pam_oauth2_device.so

%.o: %.c %.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

pam_oauth2_device.so: $(objects)
	$(CXX) -shared $^ $(LDLIBS) -o $@

clean:
	rm -f $(objects)
	rm -f pam_oauth2_device.so

install: pam_oauth2_device.so
	strip pam_oauth2_device.so
	install -D -t $(DESTDIR)$(PREFIX)/lib64/security pam_oauth2_device.so
	install -m 600 -D config_template.json $(DESTDIR)$(PREFIX)/etc/pam_oauth2_device/config.json
