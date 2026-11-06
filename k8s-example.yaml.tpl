# Kubernetes example. One pod with two containers: the official ClamAV image and our HTTP service.
# Both run as non-root with a read-only root filesystem. This was tested with
# docker, not on Fargate.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: staging-antivirus-deployment
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: staging-antivirus
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: staging-antivirus
    spec:
      securityContext:
        fsGroup: 101
      containers:
        - name: clamd
          image: clamav/clamav:stable@sha256:6d87c712e3391e13c1ba6e05dfb074d4b1ddb5a6834b23bb9da990d2a4ef042a
          # The image's /init needs root and a writable filesystem, so this runs
          # clamd and freshclam directly. Signatures start from the ones in the
          # image, copied to a writable folder that freshclam can update.
          command: ["sh", "-c"]
          args:
            - |
              cp /var/lib/clamav/* /db/
              grep -v -E "^(LogFile|User|Foreground|DatabaseDirectory)" /etc/clamav/clamd.conf > /tmp/clamd.conf
              cat >> /tmp/clamd.conf <<EOF
              DatabaseDirectory /db
              MaxFileSize 1600M
              StreamMaxLength 1600M
              MaxScanSize 4000M
              AlertExceedsMax yes
              Foreground yes
              EOF
              grep -v -E "^(UpdateLogFile|DatabaseOwner|DatabaseDirectory|NotifyClamd|Foreground)" /etc/clamav/freshclam.conf > /tmp/freshclam.conf
              echo "DatabaseDirectory /db" >> /tmp/freshclam.conf
              echo "NotifyClamd /tmp/clamd.conf" >> /tmp/freshclam.conf
              freshclam --daemon --foreground --stdout --checks=1 --config-file=/tmp/freshclam.conf &
              exec clamd --config-file=/tmp/clamd.conf
          securityContext:
            runAsUser: 100
            runAsGroup: 101
            readOnlyRootFilesystem: true
          resources:
            requests:
              cpu: "1"
              memory: "3Gi"
          livenessProbe:
            tcpSocket:
              port: 3310
            initialDelaySeconds: 120
            periodSeconds: 30
          volumeMounts:
            - { name: clamd-tmp, mountPath: /tmp }
            - { name: clamd-run, mountPath: /run/clamav }
            - { name: clamd-db, mountPath: /db }
        - name: service
          image: ${ANTIVIRUS_SERVICE_IMAGE}
          env:
            - { name: CLAMD_HOST, value: localhost }
            - { name: MAX_FILE_SIZE_MB, value: "1600" }
          ports:
            - containerPort: 8000
          securityContext:
            runAsUser: 10001
            readOnlyRootFilesystem: true
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
          # Ready only once clamd has its signatures loaded.
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            periodSeconds: 10
          livenessProbe:
            tcpSocket:
              port: 8000
            periodSeconds: 30
          volumeMounts:
            - { name: scans, mountPath: /scans }
            - { name: service-tmp, mountPath: /tmp }
      volumes:
        # Files waiting for a scan. Each one also uses space in clamd-tmp while
        # it is scanned, and Fargate limits the pod's total ephemeral storage.
        - { name: scans, emptyDir: {} }
        - { name: service-tmp, emptyDir: {} }
        - { name: clamd-tmp, emptyDir: {} }
        - { name: clamd-run, emptyDir: {} }
        - { name: clamd-db, emptyDir: {} }
---
apiVersion: v1
kind: Service
metadata:
  name: staging-antivirus
  namespace: ${NAMESPACE}
spec:
  selector:
    app: staging-antivirus
  ports:
    - port: 8000
      targetPort: 8000
