import { prop } from '@typegoose/typegoose';
import { Base } from '@typegoose/typegoose/lib/defaultClasses';

export interface UserModel extends Base {}

export class UserModel {
	@prop({ unique: true })
	email: string;

	@prop()
	password: string;

	@prop({ default: false })
	isAdmin?: boolean;

	@prop({ default: [] })
	favorites?: [];
}
