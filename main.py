"""
CitasYa Backend Patch v3.0
Maneja las rutas admin directamente y proxea todo lo demás al backend original.
"""

import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header, Query, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
