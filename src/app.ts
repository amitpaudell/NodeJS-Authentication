import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRouter from './routes/auth.routes'
import userRouter from './routes/user.routes'
import adminRouter from './routes/admin.routes'

dotenv.config();

const app=express();

app.use(express.json());
app.use(cookieParser());

app.get('/health',(_req,res)=>{
  res.json({status:"ok"})
});

app.use('/auth',authRouter);
app.use('/user',userRouter);
app.use('/admin',adminRouter)


export default app;
