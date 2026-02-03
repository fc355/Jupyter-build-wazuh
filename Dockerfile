FROM jupyter/datascience-notebook:latest

USER root

# --- Python & Bash (เหมือนเดิม) ---
RUN mkdir -p /etc/ipython/startup
COPY 00-audit.py /etc/ipython/startup/
RUN chmod 644 /etc/ipython/startup/00-audit.py

COPY bash_audit.sh /etc/profile.d/bash_audit.sh
RUN chmod 644 /etc/profile.d/bash_audit.sh
RUN echo "source /etc/profile.d/bash_audit.sh" >> /etc/bash.bashrc

USER ${NB_UID}