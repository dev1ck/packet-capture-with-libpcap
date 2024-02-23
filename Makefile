CXX = g++
CXXFLAGS = -std=c++17 -Wall -g
TARGET = cap
SRCS = main.cpp ApplicationManager.cpp CaptureEngine.cpp PacketParser.cpp SessionData.cpp Gzip.cpp
OBJS = $(SRCS:.cpp=.o)
LDFLAGS = -lpcap -lz -pthread

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJS)
