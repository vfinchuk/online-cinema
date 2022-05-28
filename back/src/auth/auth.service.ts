import {
	BadRequestException,
	Injectable,
	UnauthorizedException,
} from '@nestjs/common';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { InjectModel } from 'nestjs-typegoose';
import { hash, genSalt, compare } from 'bcryptjs';

import { UserModel } from 'src/user/user.model';
import { AuthDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
	constructor(
		@InjectModel(UserModel) private readonly UserModel: ModelType<UserModel>,
		private readonly jwtService: JwtService
	) {}

	async login(dto: AuthDto) {
		const user = await this.validateUser(dto);

		const tokens = await this.issuePairToken(String(user._id));

		return {
			user: this.getUserFields(user),
			...tokens,
		};
	}

	async register(dto: AuthDto) {
		const oldUser = await this.UserModel.findOne({ email: dto.email });

		if (oldUser) {
			throw new BadRequestException(
				`User with ${dto.email} email already exist in the system`
			);
		}

		const salt = await genSalt(10);

		const newUser = new this.UserModel({
			email: dto.email,
			password: await hash(dto.password, salt),
		});

		newUser.save();

		const tokens = await this.issuePairToken(String(newUser._id));

		return {
			user: this.getUserFields(newUser),
			...tokens,
		};
	}

	async validateUser(dto: AuthDto): Promise<UserModel> {
		const user = await this.UserModel.findOne({ email: dto.email });

		if (!user) {
			throw new UnauthorizedException('User not found');
		}

		const isPasswordValid = await compare(dto.password, user.password);

		if (!isPasswordValid) {
			throw new UnauthorizedException('Invalid password');
		}

		return user;
	}

	async issuePairToken(userId: string) {
		const data = { _id: userId };

		const refreshToken = await this.jwtService.signAsync(data, {
			expiresIn: '15d',
		});

		const accessToken = await this.jwtService.signAsync(data, {
			expiresIn: '1h',
		});

		return {
			refreshToken,
			accessToken,
		};
	}

	getUserFields({ _id, email, isAdmin }: UserModel) {
		return {
			_id,
			email,
			isAdmin,
		};
	}
}
