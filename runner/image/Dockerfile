FROM python:3.12-slim
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 MPLBACKEND=Agg
RUN pip install pandas==2.2.3 numpy==2.1.3 matplotlib==3.9.2 \
 && useradd -u 65534 -M -s /usr/sbin/nologin sandbox 2>/dev/null || true
# Pre-build matplotlib's font cache so the read-only sandbox doesn't spend ~8s on it every run.
RUN MPLCONFIGDIR=/opt/mplcache python -c "import matplotlib.pyplot as plt; plt.figure()" \
 && chmod -R a+rX /opt/mplcache
WORKDIR /job
