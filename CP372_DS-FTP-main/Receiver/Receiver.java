import java.net.*;
import java.io.*;
import java.util.*;

/**
 * DS-FTP Receiver Implementation
 * 
 * Implements both Stop-and-Wait and Go-Back-N protocol variants
 * Handles ACK dropping based on Reliability Number (RN) via ChaosEngine
 * 
 * Command line: java Receiver <sender_ip> <sender_ack_port> <rcv_data_port> <output_file> <RN>
 */
public class Receiver {
    
    // Socket for receiving data packets
    private DatagramSocket dataSocket;
    
    // Receiver's listening port
    private int rcvDataPort;
    
    // Sender's address and port for ACKs
    private InetAddress senderAddress;
    private int senderAckPort;
    
    // Output file
    private String outputFileName;
    private FileOutputStream fileOutputStream;
    
    // Reliability Number for ACK dropping
    private int rn;
    
    // Protocol state
    private int expectedSeqNum = 0;      // Next expected sequence number
    private int lastAckSent = -1;        // Last ACK sent (cumulative for GBN)
    private int ackCount = 0;             // Counter for ChaosEngine ACK dropping
    
    // GBN specific: Buffer for out-of-order packets
    private Map<Integer, DSPacket> packetBuffer;
    private boolean isGBN = false;        // Will be detected from packet flow
    private int lastSeqNum = -1;           // Last received sequence number
    private int outOfOrderCount = 0;       // Count of out-of-order packets to detect GBN
    
    // Window size for GBN receiver
    private static final int RECEIVER_WINDOW_SIZE = 32;
    
    // Debug mode - set to true for video to show detailed output
    private boolean debugMode = true;
    
    // Statistics
    private int packetsReceived = 0;
    private int duplicatePackets = 0;
    private int acksSent = 0;
    private int acksDropped = 0;
    
    public Receiver(String senderIp, int senderAckPort, int rcvDataPort, 
                    String outputFile, int rn) throws Exception {
        
        this.senderAddress = InetAddress.getByName(senderIp);
        this.senderAckPort = senderAckPort;
        this.rcvDataPort = rcvDataPort;
        this.outputFileName = outputFile;
        this.rn = rn;
        
        // Initialize buffer for GBN
        this.packetBuffer = new HashMap<>();
        
        // Create socket for receiving data - with address reuse
        dataSocket = new DatagramSocket(rcvDataPort);
        dataSocket.setReuseAddress(true);
        
        // Setup output file
        fileOutputStream = new FileOutputStream(outputFileName);
        
        log("==========================================");
        log("DS-FTP Receiver Started");
        log("==========================================");
        log("Listening on port: " + rcvDataPort);
        log("Sending ACKs to: " + senderIp + ":" + senderAckPort);
        log("Reliability Number (RN): " + rn);
        log("==========================================");
    }
    
    /**
     * Main receiver loop
     */
    public void run() throws Exception {
        boolean transferComplete = false;
        
        log("Waiting for SOT packet...");
        
        while (!transferComplete) {
            try {
                // Receive packet
                byte[] receiveBuffer = new byte[DSPacket.MAX_PACKET_SIZE];
                DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                dataSocket.receive(receivePacket);
                
                // Parse packet
                DSPacket packet = new DSPacket(receivePacket.getData());
                packetsReceived++;
                
                log("\n--- Received Packet ---");
                log("Type: " + packet.getType() + 
                    " (SOT=0, DATA=1, ACK=2, EOT=3)");
                log("Sequence: " + packet.getSeqNum());
                log("Length: " + packet.getLength() + " bytes");
                
                // Process based on packet type
                switch (packet.getType()) {
                    case DSPacket.TYPE_SOT:
                        handleSOT(packet);
                        break;
                        
                    case DSPacket.TYPE_DATA:
                        handleData(packet);
                        break;
                        
                    case DSPacket.TYPE_EOT:
                        handleEOT(packet);
                        transferComplete = true;
                        break;
                        
                    default:
                        log("WARNING: Unknown packet type " + packet.getType());
                }
                
            } catch (SocketTimeoutException e) {
                // Timeout ignored - no packet received
            } catch (Exception e) {
                log("Error processing packet: " + e.getMessage());
            }
        }
        
        cleanup();
    }
    
    /**
     * Handle SOT (Start of Transmission) packet
     */
    private void handleSOT(DSPacket packet) throws Exception {
        if (packet.getSeqNum() != 0) {
            log("ERROR: SOT packet has wrong sequence number: " + packet.getSeqNum());
            return;
        }
        
        log("\n*** HANDSHAKE ***");
        log("Received SOT (Start of Transmission)");
        
        // Send ACK for SOT
        sendACK(0);
        
        // Reset protocol state
        expectedSeqNum = 1;
        lastAckSent = 0;
        packetBuffer.clear();
        isGBN = false;
        lastSeqNum = -1;
        outOfOrderCount = 0;
        
        log("Ready to receive data packets (expecting seq=1)");
    }
    
    /**
     * Handle DATA packet - with protocol detection
     */
    private void handleData(DSPacket packet) throws Exception {
        int seqNum = packet.getSeqNum();
        
        // Detect GBN mode if we see out-of-order packets
        if (!isGBN && lastSeqNum != -1) {
            int expectedNext = (lastSeqNum + 1) % 128;
            if (seqNum != expectedNext) {
                outOfOrderCount++;
                log("Out-of-order detected: got " + seqNum + ", expected " + expectedNext);
                log("Out-of-order count: " + outOfOrderCount);
                
                if (outOfOrderCount >= 3) {
                    isGBN = true;
                    log("*** SWITCHING TO GBN MODE ***");
                    packetBuffer.clear();
                }
            } else {
                // Reset counter if we get in-order packets
                outOfOrderCount = Math.max(0, outOfOrderCount - 1);
            }
        }
        
        lastSeqNum = seqNum;
        
        // Handle based on detected mode
        if (isGBN) {
            handleDataGBN(packet);
        } else {
            handleDataStopAndWait(packet);
        }
    }
    
    /**
     * Handle DATA packet for Stop-and-Wait mode
     */
    private void handleDataStopAndWait(DSPacket packet) throws Exception {
        int seqNum = packet.getSeqNum();
        
        if (seqNum == expectedSeqNum) {
            // Expected packet - write and ACK
            log("✓ Stop-and-Wait: Received expected packet " + seqNum);
            
            // Write payload to file
            if (packet.getLength() > 0) {
                fileOutputStream.write(packet.getPayload());
                fileOutputStream.flush();
                log("  Wrote " + packet.getLength() + " bytes to file");
            }
            
            // Send ACK
            sendACK(seqNum);
            
            // Update expected sequence
            expectedSeqNum = (expectedSeqNum + 1) % 128;
            lastAckSent = seqNum;
            
            log("  Next expected sequence: " + expectedSeqNum);
            
        } else {
            // Duplicate or out-of-order - resend last ACK
            log("✗ Stop-and-Wait: Received unexpected packet " + seqNum + 
                ", expected " + expectedSeqNum);
            
            if (lastAckSent >= 0) {
                log("  Resending ACK " + lastAckSent);
                sendACK(lastAckSent);
            }
            duplicatePackets++;
        }
    }
    
    /**
     * Handle DATA packet for Go-Back-N mode with buffering
     */
    private void handleDataGBN(DSPacket packet) throws Exception {
        int seqNum = packet.getSeqNum();
        
        log("GBN: Received packet " + seqNum + ", expectedSeq=" + expectedSeqNum);
        
        // Check if packet is within receive window
        if (isWithinWindow(seqNum, expectedSeqNum, RECEIVER_WINDOW_SIZE)) {
            // Packet is within window - buffer it if not already received
            if (!packetBuffer.containsKey(seqNum)) {
                packetBuffer.put(seqNum, packet);
                log("GBN: Buffered packet " + seqNum + " (buffer size: " + packetBuffer.size() + ")");
            } else {
                log("GBN: Duplicate packet " + seqNum + " ignored");
                duplicatePackets++;
            }
            
            // Deliver contiguous packets in order
            deliverBufferedPackets();
            
        } else {
            // Packet outside window - discard and resend cumulative ACK
            log("GBN: Packet " + seqNum + " outside window - discarding");
            if (lastAckSent >= 0) {
                log("GBN: Resending cumulative ACK " + lastAckSent);
                sendACK(lastAckSent);
            }
        }
    }
    
    /**
     * Check if a sequence number is within the receive window
     */
    private boolean isWithinWindow(int seqNum, int expected, int windowSize) {
        // Handle modulo 128 arithmetic
        if (expected <= (expected + windowSize) % 128) {
            // No wrap-around
            return seqNum >= expected && seqNum <= expected + windowSize;
        } else {
            // Wrap-around
            return seqNum >= expected || seqNum <= (expected + windowSize) % 128;
        }
    }
    
    /**
     * Deliver any buffered packets that are now in order
     */
    private void deliverBufferedPackets() throws Exception {
        boolean delivered;
        int deliveredCount = 0;
        
        do {
            delivered = false;
            
            // Check if expected packet is in buffer
            if (packetBuffer.containsKey(expectedSeqNum)) {
                DSPacket packet = packetBuffer.remove(expectedSeqNum);
                
                // Write payload
                if (packet.getLength() > 0) {
                    fileOutputStream.write(packet.getPayload());
                    fileOutputStream.flush();
                }
                
                log("GBN: Delivered packet " + expectedSeqNum);
                deliveredCount++;
                
                // Update expected sequence
                expectedSeqNum = (expectedSeqNum + 1) % 128;
                delivered = true;
            }
            
        } while (delivered);
        
        if (deliveredCount > 0) {
            log("GBN: Delivered " + deliveredCount + " packets, new expectedSeq=" + expectedSeqNum);
        }
        
        // Send cumulative ACK for last contiguous packet
        int cumulativeAck = (expectedSeqNum - 1 + 128) % 128;
        if (cumulativeAck != lastAckSent) {
            log("GBN: Sending cumulative ACK " + cumulativeAck);
            sendACK(cumulativeAck);
            lastAckSent = cumulativeAck;
        }
    }
    
    /**
     * Handle EOT (End of Transmission) packet
     */
    private void handleEOT(DSPacket packet) throws Exception {
        log("\n*** TRANSFER COMPLETE ***");
        log("Received EOT with seq=" + packet.getSeqNum());
        
        // Verify EOT sequence number
        int expectedEotSeq = (expectedSeqNum) % 128;
        if (packet.getSeqNum() != expectedEotSeq) {
            log("WARNING: EOT sequence mismatch. Got " + packet.getSeqNum() + 
                ", expected " + expectedEotSeq);
        }
        
        // Send ACK for EOT
        log("Sending EOT ACK");
        sendACK(packet.getSeqNum());
        
        log("Transfer complete");
    }
    
    /**
     * Send ACK packet (with possible dropping via ChaosEngine)
     */
    private void sendACK(int ackSeqNum) throws Exception {
        // Increment ACK counter (1-indexed as required by ChaosEngine)
        ackCount++;
        
        // Check if this ACK should be dropped
        if (ChaosEngine.shouldDrop(ackCount, rn)) {
            acksDropped++;
            log("\n*** CHAOS ENGINE: DROPPING ACK #" + ackCount + " for seq " + ackSeqNum + " ***");
            log("    Total ACKs dropped: " + acksDropped);
            return; // Simulate loss by not sending
        }
        
        acksSent++;
        log("\n>>> Sending ACK for seq " + ackSeqNum + " (ACK #" + ackCount + ")");
        
        // Create ACK packet
        DSPacket ackPacket = new DSPacket(DSPacket.TYPE_ACK, ackSeqNum, null);
        
        // Convert to bytes
        byte[] sendData = ackPacket.toBytes();
        
        // Send to sender's ACK port
        DatagramPacket sendPacket = new DatagramPacket(
            sendData, sendData.length, senderAddress, senderAckPort
        );
        
        dataSocket.send(sendPacket);
    }
    
    /**
     * Verify the received file
     */
    private void verifyReceivedFile() {
        File received = new File(outputFileName);
        
        log("\n==========================================");
        log("FILE TRANSFER VERIFICATION");
        log("==========================================");
        log("Received file: " + outputFileName);
        log("Received file size: " + received.length() + " bytes");
        log("\nStatistics:");
        log("  Packets received: " + packetsReceived);
        log("  Duplicate packets: " + duplicatePackets);
        log("  ACKs sent: " + acksSent);
        log("  ACKs dropped: " + acksDropped);
        log("  Final expectedSeqNum: " + expectedSeqNum);
        log("==========================================\n");
    }
    
    /**
     * Clean up resources
     */
    private void cleanup() throws Exception {
        if (fileOutputStream != null) {
            fileOutputStream.close();
        }
        
        if (dataSocket != null && !dataSocket.isClosed()) {
            dataSocket.close();
        }
        
        // Verify the received file
        verifyReceivedFile();
        
        log("Receiver finished. Output file: " + outputFileName);
    }
    
    /**
     * Logging utility
     */
    private void log(String message) {
        if (debugMode) {
            String timestamp = new java.text.SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
            String logMessage = "[" + timestamp + "] " + message;
            System.out.println(logMessage);
        }
    }
    
    public static void main(String[] args) {
        // Validate command line arguments
        if (args.length != 5) {
            System.err.println("Usage: java Receiver <sender_ip> <sender_ack_port> " +
                             "<rcv_data_port> <output_file> <RN>");
            System.err.println("Example: java Receiver 127.0.0.1 3000 4000 received.txt 0");
            System.exit(1);
        }
        
        try {
            // Parse arguments
            String senderIp = args[0];
            int senderAckPort = Integer.parseInt(args[1]);
            int rcvDataPort = Integer.parseInt(args[2]);
            String outputFile = args[3];
            int rn = Integer.parseInt(args[4]);
            
            // Validate RN
            if (rn < 0) {
                System.err.println("RN must be >= 0");
                System.exit(1);
            }
            
            // Validate ports
            if (senderAckPort < 1024 || senderAckPort > 65535 || 
                rcvDataPort < 1024 || rcvDataPort > 65535) {
                System.err.println("Ports must be between 1024 and 65535");
                System.exit(1);
            }
            
            // Create and run receiver
            Receiver receiver = new Receiver(senderIp, senderAckPort, rcvDataPort, outputFile, rn);
            receiver.run();
            
        } catch (NumberFormatException e) {
            System.err.println("Invalid port or RN number: " + e.getMessage());
            System.exit(1);
        } catch (SocketException e) {
            System.err.println("Socket error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (FileNotFoundException e) {
            System.err.println("Output file error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
