import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRouter from './routes/auth.routes'
import userRouter from './routes/user.routes'

dotenv.config();

const app=express();

app.use(express.json());
app.use(cookieParser());

app.get('/health',(_req,res)=>{
  res.json({status:"ok"})
});

app.use('/auth',authRouter);
app.use('/user',userRouter)


export default app;
